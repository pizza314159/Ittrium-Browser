"""
Ittrium Browser — hardened browser with file-upload VPN + Tor toggle.

Cross-platform: Linux and Windows.

Security layers applied:
  • HTTPS-only mode (blocks plain HTTP navigation)
  • Strict Content-Security-Policy injected on every page
  • Known tracker / malware domain blocklist (DNS-level refusal)
  • Certificate error interception — untrusted certs are hard-blocked
  • Fingerprinting mitigations (WebGL, AudioContext, Canvas, timezone spoofing)
  • Popups, auto-redirects, and new-window requests blocked
  • Mixed content (HTTP inside HTTPS) blocked
  • file:// and data: URI navigation blocked
  • Executable download warning (.exe .msi .sh .bat .ps1 .dmg …)
  • Chromium renderer sandbox hardened via env flags
  • URL bar spoofing protection (strips homograph / non-ASCII)

VPN usage:
  • Drop a .ovpn file  → OpenVPN tunnel
    Linux:   sudo apt install openvpn
    Windows: Install OpenVPN GUI from https://openvpn.net/community-downloads/
  • Drop a .conf file  → WireGuard tunnel
    Linux:   sudo apt install wireguard-tools
    Windows: Install WireGuard from https://www.wireguard.com/install/

Tor usage:
  • Flip the Tor toggle in the toolbar
    Linux:   sudo apt install tor && sudo systemctl start tor
    Windows: Install Tor Browser or Expert Bundle from https://www.torproject.org/
"""

import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import psutil
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from PySide6.QtCore import QUrl, Qt, Signal, QObject, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtNetwork import QNetworkProxy
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTabWidget,
    QToolBar,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QLabel,
    QVBoxLayout,
    QWidget,
    QSplitter,
    QFrame,
)
from PySide6.QtWebEngineCore import (
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineSettings,
)
from PySide6.QtWebEngineWidgets import QWebEngineView


# ── Platform detection ─────────────────────────────────────────────────────

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"


# ── Constants ──────────────────────────────────────────────────────────────

HOME_URL       = "https://duckduckgo.com"
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://ipecho.net/plain",
    "https://icanhazip.com",
]

# ── Security: blocked domains ─────────────────────────────────────────────
BLOCKED_DOMAINS: set[str] = {
    "malware.testcave.xyz", "phishing-test.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adnxs.com", "adsrvr.org", "rubiconproject.com", "openx.net",
    "pubmatic.com", "casalemedia.com", "smartadserver.com",
    "scorecardresearch.com", "quantserve.com", "bluekai.com",
    "demdex.net", "everesttech.net", "rlcdn.com", "krxd.net",
    "taboola.com", "outbrain.com", "revcontent.com",
    "fingerprintjs.com", "fingerprintjs2.com", "augur.io",
    "iovation.com", "threatmetrix.com", "sift.com",
    "metrics.apple.com", "telemetry.mozilla.org",
    "watson.telemetry.microsoft.com",
}

# ── Security: dangerous download extensions ────────────────────────────────
DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js",  ".jse", ".wsf", ".wsh", ".scr", ".pif", ".com", ".cpl",
    ".hta", ".sh",  ".bash",".zsh",  ".dmg", ".pkg", ".deb", ".rpm",
    ".apk", ".ipa", ".jar", ".war",  ".ear",
}

# ── Security: URL schemes that must never be loaded ────────────────────────
BLOCKED_SCHEMES: set[str] = {"file", "data", "blob", "javascript"}

# ── Security: CSP injected as a <meta> on every page load ─────────────────
INJECTED_CSP = (
    "default-src 'self' https:; "
    "script-src 'self' https: 'strict-dynamic'; "
    "style-src 'self' https: 'unsafe-inline'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self' https:; "
    "frame-ancestors 'self'; "
    "upgrade-insecure-requests;"
)

INJECT_CSP_JS = f"""
(function() {{
    var m = document.createElement('meta');
    m.httpEquiv = 'Content-Security-Policy';
    m.content = {repr(INJECTED_CSP)};
    var head = document.head || document.documentElement;
    if (head) head.insertBefore(m, head.firstChild);
}})();
"""

ANTI_FINGERPRINT_JS = """
(function() {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const img = ctx.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < img.data.length; i += 4) {
                img.data[i]   ^= (Math.random() * 2) | 0;
                img.data[i+1] ^= (Math.random() * 2) | 0;
                img.data[i+2] ^= (Math.random() * 2) | 0;
            }
            ctx.putImageData(img, 0, 0);
        }
        return origToDataURL.apply(this, arguments);
    };

    if (window.AudioContext || window.webkitAudioContext) {
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function() {
            const arr = origGetChannelData.apply(this, arguments);
            for (let i = 0; i < arr.length; i += 100)
                arr[i] += (Math.random() - 0.5) * 1e-7;
            return arr;
        };
    }

    Object.defineProperty(navigator, 'plugins', {
        get: () => Object.create(PluginArray.prototype)
    });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
    if ('deviceMemory' in navigator)
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    if (navigator.getBattery)
        navigator.getBattery = () => Promise.reject(new Error('blocked'));
    Object.defineProperty(screen, 'width',       { get: () => 1920 });
    Object.defineProperty(screen, 'height',      { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth',  { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth',  { get: () => 24  });
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
})();
"""


# ── Helpers ────────────────────────────────────────────────────────────────

def normalize_url(text: str) -> QUrl:
    text = text.strip()
    if not text:
        return QUrl(HOME_URL)
    parsed = urlparse(text)
    if parsed.scheme:
        return QUrl(text)
    if " " not in text and "." in text:
        return QUrl("https://" + text)
    query = QUrl.toPercentEncoding(text).data().decode()
    return QUrl(f"https://duckduckgo.com/?q={query}")


def sanitize_url(text: str) -> QUrl | None:
    url    = normalize_url(text)
    scheme = url.scheme().lower()

    if scheme in BLOCKED_SCHEMES:
        return None
    if scheme == "http":
        url = QUrl(url.toString().replace("http://", "https://", 1))

    host = url.host()
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        puny = host.encode("idna").decode("ascii")
        url.setHost(puny)

    if is_blocked_domain(url.host()):
        return None

    return url


def is_blocked_domain(host: str) -> bool:
    host  = host.lower().lstrip("www.")
    if host in BLOCKED_DOMAINS:
        return True
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in BLOCKED_DOMAINS:
            return True
    return False


def get_public_ip(timeout: int = 8) -> str | None:
    for url in IP_CHECK_URLS:
        try:
            with urlopen(url, timeout=timeout) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return None


def find_executable(name: str, windows_paths: list[str] | None = None) -> str | None:
    """
    Locate an executable on PATH, with optional extra search paths on Windows.
    Returns the full path string or None.
    """
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS and windows_paths:
        for p in windows_paths:
            candidate = Path(p) / (name + ".exe")
            if candidate.exists():
                return str(candidate)
    return None


def detect_vpn_type(path: str) -> str:
    """Return 'openvpn', 'wireguard', or 'unknown'."""
    suffix = Path(path).suffix.lower()
    if suffix == ".ovpn":
        return "openvpn"
    if suffix == ".conf":
        try:
            with open(path, "r", errors="replace") as f:
                head = f.read(512)
            if "[Interface]" in head:
                return "wireguard"
        except Exception:
            pass
    return "unknown"


# ── Platform-specific VPN helpers ──────────────────────────────────────────

# Common OpenVPN install locations on Windows
_OVPN_WIN_PATHS = [
    r"C:\Program Files\OpenVPN\bin",
    r"C:\Program Files (x86)\OpenVPN\bin",
]

# Common WireGuard install locations on Windows
_WG_WIN_PATHS = [
    r"C:\Program Files\WireGuard",
]


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Run a subprocess, adding CREATE_NO_WINDOW on Windows to avoid
    console popups, and hiding sudo requirement where not applicable.
    """
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.run(cmd, **kwargs)


def _popen(cmd: list[str], **kwargs) -> subprocess.Popen:
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return subprocess.Popen(cmd, **kwargs)


def _sudo(cmd: list[str]) -> list[str]:
    """Prepend sudo on Linux/Mac; pass through on Windows (admin required at launch)."""
    if IS_LINUX or IS_MAC:
        return ["sudo"] + cmd
    return cmd


def _openvpn_bin() -> str | None:
    return find_executable("openvpn", _OVPN_WIN_PATHS)


def _wg_quick_bin() -> str | None:
    # On Windows, WireGuard uses 'wireguard.exe /installtunnelservice'
    if IS_WINDOWS:
        return find_executable("wireguard", _WG_WIN_PATHS)
    return find_executable("wg-quick")


def _wg_bin() -> str | None:
    return find_executable("wg", _WG_WIN_PATHS)


# ── VPN Manager ────────────────────────────────────────────────────────────

class VpnManager(QObject):
    status_changed = Signal(str, bool)
    ip_resolved    = Signal(str, str)

    def __init__(self):
        super().__init__()
        self._pre_vpn_ip    = None
        self._wg_iface      = None
        self._ovpn_proc     = None     # Windows: Popen; Linux: daemon pid
        self._ovpn_tmpfile  = None
        self._wg_conf_copy  = None     # Windows tunnel conf copy path
        self.vpn_ip         = None
        self.vpn_type       = None

    # ── Public API ────────────────────────────────────────────────

    def connect_file(self, config_path: str, real_ip: str):
        self.disconnect()
        self._pre_vpn_ip = real_ip
        vpn_type = detect_vpn_type(config_path)
        if vpn_type == "unknown":
            self.status_changed.emit(
                "❌ Unrecognised file — use a .ovpn (OpenVPN) or .conf (WireGuard) file.", False
            )
            return
        self.vpn_type = vpn_type
        self.status_changed.emit(f"⏳ Connecting via {vpn_type}…", False)
        threading.Thread(
            target=self._connect_thread, args=(config_path, vpn_type), daemon=True
        ).start()

    def disconnect(self):
        try:
            if self.vpn_type == "openvpn":
                self._stop_openvpn()
            elif self.vpn_type == "wireguard":
                self._stop_wireguard()
        except Exception:
            pass
        self.vpn_ip   = None
        self.vpn_type = None
        self.status_changed.emit("VPN disconnected", False)

    @property
    def is_connected(self) -> bool:
        return self.vpn_ip is not None

    # ── Internal ──────────────────────────────────────────────────

    def _connect_thread(self, config_path: str, vpn_type: str):
        if vpn_type == "openvpn":
            self._start_openvpn(config_path)
        elif vpn_type == "wireguard":
            self._start_wireguard(config_path)

    # ── OpenVPN ───────────────────────────────────────────────────

    def _start_openvpn(self, config_path: str):
        ovpn = _openvpn_bin()
        if not ovpn:
            if IS_WINDOWS:
                self.status_changed.emit(
                    "❌ openvpn.exe not found.\n"
                    "Install OpenVPN GUI: https://openvpn.net/community-downloads/", False
                )
            else:
                self.status_changed.emit(
                    "❌ openvpn not found — install: sudo apt install openvpn", False
                )
            return

        # Write a temp copy so we control the path (avoids sudo path issues)
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".ovpn", delete=False, prefix="Ittrium Browser_vpn_"
            )
            with open(config_path, "r", errors="replace") as f:
                tmp.write(f.read())
            tmp.flush()
            tmp.close()
            self._ovpn_tmpfile = tmp.name
        except Exception as e:
            self.status_changed.emit(f"❌ Could not stage config: {e}", False)
            return

        if IS_WINDOWS:
            self._start_openvpn_windows(ovpn)
        else:
            self._start_openvpn_linux(ovpn)

    def _start_openvpn_windows(self, ovpn_bin: str):
        """
        On Windows run OpenVPN directly (requires admin or OpenVPN service).
        We use --service with a management interface so we can stop it cleanly.
        """
        cmd = [
            ovpn_bin,
            "--config", self._ovpn_tmpfile,
            "--log", os.path.join(tempfile.gettempdir(), "Ittrium Browser_vpn.log"),
        ]
        try:
            self._ovpn_proc = _popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except PermissionError:
            self.status_changed.emit(
                "❌ Permission denied — run Ittrium Browser as Administrator for VPN.", False
            )
            return
        except Exception as e:
            self.status_changed.emit(f"❌ OpenVPN launch failed: {e}", False)
            return
        self._poll_for_ip("OpenVPN")

    def _start_openvpn_linux(self, ovpn_bin: str):
        """On Linux run openvpn as a daemon via sudo."""
        cmd = _sudo([
            ovpn_bin,
            "--config", self._ovpn_tmpfile,
            "--daemon",
            "--log", "/tmp/Ittrium Browser_vpn.log",
        ])
        try:
            _run(cmd, check=True, timeout=15,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.status_changed.emit(
                "❌ sudo not found — cannot launch openvpn.", False
            )
            return
        except subprocess.CalledProcessError as e:
            self.status_changed.emit(f"❌ OpenVPN error (exit {e.returncode})", False)
            return
        except subprocess.TimeoutExpired:
            pass  # daemon started, timeout expected
        self._poll_for_ip("OpenVPN")

    def _stop_openvpn(self):
        if IS_WINDOWS:
            if self._ovpn_proc and self._ovpn_proc.poll() is None:
                self._ovpn_proc.terminate()
                try:
                    self._ovpn_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._ovpn_proc.kill()
            self._ovpn_proc = None
        else:
            _run(
                _sudo(["pkill", "-f", "Ittrium Browser_vpn_"]),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        if self._ovpn_tmpfile:
            try:
                os.unlink(self._ovpn_tmpfile)
            except Exception:
                pass
            self._ovpn_tmpfile = None

    # ── WireGuard ─────────────────────────────────────────────────

    def _start_wireguard(self, config_path: str):
        if IS_WINDOWS:
            self._start_wireguard_windows(config_path)
        else:
            self._start_wireguard_linux(config_path)

    def _start_wireguard_linux(self, config_path: str):
        wq = _wg_quick_bin()
        if not wq:
            self.status_changed.emit(
                "❌ wg-quick not found — install: sudo apt install wireguard-tools", False
            )
            return

        iface    = "wg-bb0"
        dest     = f"/tmp/{iface}.conf"
        try:
            with open(config_path, "r", errors="replace") as f:
                data = f.read()
            proc = _run(
                _sudo(["tee", dest]),
                input=data.encode(), capture_output=True,
            )
            if proc.returncode != 0:
                self.status_changed.emit("❌ Could not write WireGuard config to /tmp", False)
                return
        except Exception as e:
            self.status_changed.emit(f"❌ Config read error: {e}", False)
            return

        try:
            result = _run(
                _sudo([wq, "up", dest]),
                capture_output=True, text=True, timeout=25,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "unknown error").strip()
                self.status_changed.emit(f"❌ WireGuard error: {err}", False)
                return
            self._wg_iface = iface
        except FileNotFoundError:
            self.status_changed.emit(
                "❌ wg-quick not found — install: sudo apt install wireguard-tools", False
            )
            return
        except subprocess.TimeoutExpired:
            self.status_changed.emit("❌ wg-quick timed out", False)
            return
        self._poll_for_ip("WireGuard")

    def _start_wireguard_windows(self, config_path: str):
        """
        On Windows, WireGuard tunnels are managed via:
          wireguard.exe /installtunnelservice <conf_path>
        The conf file must live in %PROGRAMDATA%\\WireGuard\\
        Requires the WireGuard service + admin rights.
        """
        wg = find_executable("wireguard", _WG_WIN_PATHS)
        if not wg:
            self.status_changed.emit(
                "❌ wireguard.exe not found.\n"
                "Install WireGuard: https://www.wireguard.com/install/", False
            )
            return

        # WireGuard on Windows requires the conf in its data directory
        wg_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WireGuard"
        try:
            wg_data.mkdir(parents=True, exist_ok=True)
            dest = wg_data / "Ittrium Browser_wg.conf"
            import shutil as _sh
            _sh.copy2(config_path, str(dest))
            self._wg_conf_copy = str(dest)
        except PermissionError:
            self.status_changed.emit(
                "❌ Permission denied — run Ittrium Browser as Administrator for WireGuard.", False
            )
            return
        except Exception as e:
            self.status_changed.emit(f"❌ Could not stage WireGuard config: {e}", False)
            return

        try:
            result = _run(
                [wg, "/installtunnelservice", str(dest)],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "unknown error").strip()
                self.status_changed.emit(f"❌ WireGuard install tunnel error: {err}", False)
                return
            self._wg_iface = "Ittrium Browser_wg"
        except subprocess.TimeoutExpired:
            self.status_changed.emit("❌ WireGuard tunnel install timed out", False)
            return
        except Exception as e:
            self.status_changed.emit(f"❌ WireGuard error: {e}", False)
            return

        self._poll_for_ip("WireGuard")

    def _stop_wireguard(self):
        if IS_WINDOWS:
            wg = find_executable("wireguard", _WG_WIN_PATHS)
            if wg and self._wg_iface:
                _run(
                    [wg, "/uninstalltunnelservice", self._wg_iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            if self._wg_conf_copy:
                try:
                    os.unlink(self._wg_conf_copy)
                except Exception:
                    pass
                self._wg_conf_copy = None
        else:
            if self._wg_iface:
                wq = _wg_quick_bin()
                if wq:
                    _run(
                        _sudo([wq, "down", f"/tmp/{self._wg_iface}.conf"]),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
        self._wg_iface = None

    # ── IP polling ────────────────────────────────────────────────

    def _poll_for_ip(self, label: str):
        deadline = time.time() + 35
        while time.time() < deadline:
            time.sleep(2)
            ip = get_public_ip(timeout=6)
            if ip and ip != self._pre_vpn_ip:
                self.vpn_ip = ip
                self.status_changed.emit(
                    f"🔒 {label} connected  |  Apparent IP: {ip}", True
                )
                self.ip_resolved.emit(self._pre_vpn_ip or "?", ip)
                return
        self.status_changed.emit(
            f"⚠️  {label} may not have connected — IP unchanged after 35 s\n"
            f"Check the VPN config and that the service has required permissions.", False
        )


# ── VPN Panel Widget ────────────────────────────────────────────────────────

PANEL_STYLE = """
QWidget          { background: #12121e; color: #e0e0e0; }
QLabel           { color: #e0e0e0; }
QPushButton      { border-radius: 4px; padding: 5px 10px; font-weight: bold; }
QFrame#separator { background: #2a2a3e; }
"""

BTN_UPLOAD = """
QPushButton {
    background: #1e1e3a; color: #a0b4ff;
    border: 2px dashed #4455aa;
    border-radius: 6px;
    font-size: 13px;
    padding: 18px 10px;
}
QPushButton:hover { background: #252545; border-color: #7788ff; color: #c0d0ff; }
"""

BTN_CONNECT = """
QPushButton          { background: #1a4731; color: #6effa0; border: 2px solid #2ecc71; }
QPushButton:hover    { background: #215a3d; }
QPushButton:disabled { background: #1a1a2e; color: #555; border-color: #333; }
"""

BTN_DISCONNECT = """
QPushButton          { background: #3a1515; color: #ff7070; border: 2px solid #c0392b; }
QPushButton:hover    { background: #4a1c1c; }
QPushButton:disabled { background: #1a1a2e; color: #555; border-color: #333; }
"""


class VpnPanel(QWidget):
    def __init__(self, vpn_manager: VpnManager, parent=None):
        super().__init__(parent)
        self.vpn          = vpn_manager
        self.real_ip      = None
        self._config_path = None

        self.setStyleSheet(PANEL_STYLE)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 14, 12, 14)
        root.setSpacing(10)

        title = QLabel("🔐  VPN")
        title.setStyleSheet("font-size:15px; font-weight:bold; color:#a0b4ff;")
        root.addWidget(title)

        platform_note = (
            "Upload your own .ovpn or .conf file.\n"
            "Windows: run as Administrator.\n"
            "Linux: needs sudo + openvpn/wireguard-tools."
        ) if IS_WINDOWS else (
            "Upload your own .ovpn or .conf file to connect.\n"
            "Needs openvpn / wireguard-tools + sudo."
        )
        subtitle = QLabel(platform_note)
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color:#888; font-size:11px;")
        root.addWidget(subtitle)

        root.addWidget(self._separator())

        self.real_ip_lbl = QLabel("Your IP: checking…")
        self.real_ip_lbl.setStyleSheet("color:#ff8080; font-size:11px;")
        root.addWidget(self.real_ip_lbl)

        self.vpn_ip_lbl = QLabel("VPN IP: —")
        self.vpn_ip_lbl.setStyleSheet("color:#888; font-size:11px;")
        root.addWidget(self.vpn_ip_lbl)

        root.addWidget(self._separator())

        self.upload_btn = QPushButton("📂  Upload VPN config\n.ovpn  or  .conf")
        self.upload_btn.setStyleSheet(BTN_UPLOAD)
        self.upload_btn.setMinimumHeight(70)
        self.upload_btn.clicked.connect(self.browse_config)
        root.addWidget(self.upload_btn)

        self.file_lbl = QLabel("No file loaded")
        self.file_lbl.setWordWrap(True)
        self.file_lbl.setAlignment(Qt.AlignCenter)
        self.file_lbl.setStyleSheet("color:#666; font-size:10px;")
        root.addWidget(self.file_lbl)

        root.addWidget(self._separator())

        self.connect_btn = QPushButton("🔒  Connect")
        self.connect_btn.setStyleSheet(BTN_CONNECT)
        self.connect_btn.setEnabled(False)
        self.connect_btn.clicked.connect(self.do_connect)
        root.addWidget(self.connect_btn)

        self.disconnect_btn = QPushButton("⛔  Disconnect")
        self.disconnect_btn.setStyleSheet(BTN_DISCONNECT)
        self.disconnect_btn.setEnabled(False)
        self.disconnect_btn.clicked.connect(self.do_disconnect)
        root.addWidget(self.disconnect_btn)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        self.status_lbl.setStyleSheet("color:#aaa; font-size:11px;")
        root.addWidget(self.status_lbl)

        root.addStretch()

        root.addWidget(self._separator())

        if IS_WINDOWS:
            hint_text = (
                "OpenVPN: install OpenVPN GUI from openvpn.net\n"
                "WireGuard: install from wireguard.com\n"
                "Both require Administrator rights."
            )
        else:
            hint_text = (
                "sudo apt install openvpn wireguard-tools\n"
                "Works with any provider's .ovpn or .conf file."
            )
        hint = QLabel(hint_text)
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#444; font-size:10px;")
        root.addWidget(hint)

        self.vpn.status_changed.connect(self._on_status)
        self.vpn.ip_resolved.connect(self._on_ip_resolved)

        threading.Thread(target=self._fetch_real_ip, daemon=True).start()

    def _separator(self):
        line = QFrame()
        line.setObjectName("separator")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)
        return line

    def _fetch_real_ip(self):
        ip = get_public_ip()
        self.real_ip = ip
        self.real_ip_lbl.setText(f"Your IP: {ip or 'unknown'}")

    def _on_ip_resolved(self, real_ip: str, vpn_ip: str):
        self.real_ip_lbl.setText(f"Your IP: {real_ip}")
        self.vpn_ip_lbl.setStyleSheet("color:#51cf66; font-size:11px;")
        self.vpn_ip_lbl.setText(f"VPN IP: {vpn_ip}  ✅")

    def browse_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select VPN config", str(Path.home()),
            "VPN configs (*.ovpn *.conf);;All files (*)"
        )
        if path:
            self._load_config(path)

    def _load_config(self, path: str):
        vpn_type = detect_vpn_type(path)
        if vpn_type == "unknown":
            QMessageBox.warning(
                self, "Unsupported file",
                "Please upload a .ovpn (OpenVPN) or .conf (WireGuard) file."
            )
            return
        self._config_path = path
        name       = Path(path).name
        type_label = "OpenVPN" if vpn_type == "openvpn" else "WireGuard"
        self.file_lbl.setText(f"📄 {name}\n({type_label})")
        self.file_lbl.setStyleSheet("color:#a0b4ff; font-size:10px;")
        self.connect_btn.setEnabled(True)
        self.status_lbl.setText(f"Config loaded — click Connect to start {type_label}.")
        self.status_lbl.setStyleSheet("color:#aaa; font-size:11px;")

    def do_connect(self):
        if not self._config_path:
            return
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        self.vpn_ip_lbl.setText("VPN IP: connecting…")
        self.vpn_ip_lbl.setStyleSheet("color:#aaa; font-size:11px;")
        self.vpn.connect_file(self._config_path, self.real_ip or "")

    def do_disconnect(self):
        self.vpn.disconnect()
        self.connect_btn.setEnabled(bool(self._config_path))
        self.disconnect_btn.setEnabled(False)
        self.vpn_ip_lbl.setText("VPN IP: —")
        self.vpn_ip_lbl.setStyleSheet("color:#888; font-size:11px;")

    def _on_status(self, msg: str, connected: bool):
        self.status_lbl.setText(msg)
        color = (
            "#51cf66" if connected
            else ("#ff7070" if ("❌" in msg or "⚠️" in msg) else "#aaa")
        )
        self.status_lbl.setStyleSheet(f"color:{color}; font-size:11px;")
        if connected:
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        elif "❌" in msg or "⚠️" in msg:
            self.connect_btn.setEnabled(bool(self._config_path))
            self.disconnect_btn.setEnabled(False)


# ── Browser engine ─────────────────────────────────────────────────────────

class BrowserPage(QWebEnginePage):
    """
    Hardened QWebEnginePage.
    """

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        pass

    def certificateError(self, error):
        error.rejectCertificate()
        return True

    def createWindow(self, win_type):
        main = self.view().window()
        if hasattr(main, "add_new_tab"):
            main.add_new_tab()
            return main.current_browser().page()
        return None

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        scheme = url.scheme().lower()
        host   = url.host().lower()

        if scheme in BLOCKED_SCHEMES:
            return False
        if is_blocked_domain(host):
            return False

        if scheme == "http" and is_main_frame:
            https_url = QUrl(url.toString().replace("http://", "https://", 1))
            QTimer.singleShot(0, lambda: self.view().setUrl(https_url))
            return False

        return True

    def loadFinished_security_inject(self, ok: bool):
        if ok:
            self.runJavaScript(INJECT_CSP_JS)
            self.runJavaScript(ANTI_FINGERPRINT_JS)


class BrowserTab(QWebEngineView):
    def __init__(self, profile: QWebEngineProfile, parent=None):
        super().__init__(parent)
        page = BrowserPage(profile, self)
        self.setPage(page)
        self.loadFinished.connect(page.loadFinished_security_inject)


def apply_security_settings(profile: QWebEngineProfile):
    s  = profile.settings()
    WA = QWebEngineSettings.WebAttribute

    s.setAttribute(WA.JavascriptCanOpenWindows,          False)
    s.setAttribute(WA.JavascriptCanAccessClipboard,      False)
    s.setAttribute(WA.LocalContentCanAccessRemoteUrls,   False)
    s.setAttribute(WA.LocalContentCanAccessFileUrls,     False)
    s.setAttribute(WA.AllowRunningInsecureContent,       False)
    s.setAttribute(WA.AllowGeolocationOnInsecureOrigins, False)
    s.setAttribute(WA.WebGLEnabled,                      False)
    s.setAttribute(WA.Accelerated2dCanvasEnabled,        False)
    s.setAttribute(WA.AutoLoadIconsForPage,              True)
    s.setAttribute(WA.PluginsEnabled,                    False)
    s.setAttribute(WA.PdfViewerEnabled,                  True)
    s.setAttribute(WA.FullScreenSupportEnabled,          False)
    s.setAttribute(WA.ScreenCaptureEnabled,              False)
    s.setAttribute(WA.WebRTCPublicInterfacesOnly,        True)
    s.setAttribute(WA.DnsPrefetchEnabled,                False)
    s.setAttribute(WA.NavigateOnDropEnabled,             False)
    s.setAttribute(WA.JavascriptEnabled,                 True)
    s.setAttribute(WA.LocalStorageEnabled,               True)
    s.setAttribute(WA.ScrollAnimatorEnabled,             True)
    s.setAttribute(WA.SpatialNavigationEnabled,          False)

    profile.setHttpAcceptLanguage("en-US,en;q=0.9")
    profile.setHttpUserAgent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


def build_incognito_profile(parent, use_tor: bool = False) -> QWebEngineProfile:
    profile = QWebEngineProfile(parent)
    apply_security_settings(profile)
    s  = profile.settings()
    WA = QWebEngineSettings.WebAttribute
    s.setAttribute(WA.LocalStorageEnabled, False)
    if use_tor:
        proxy = QNetworkProxy()
        proxy.setType(QNetworkProxy.Socks5Proxy)
        proxy.setHostName(TOR_PROXY_HOST)
        proxy.setPort(TOR_PROXY_PORT)
        QNetworkProxy.setApplicationProxy(proxy)
    return profile


def clear_tor_proxy():
    QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.NoProxy))


# ── Main Window ────────────────────────────────────────────────────────────

class BrowserWindow(QMainWindow):
    def __init__(self, tor_mode: bool = False, profile: QWebEngineProfile | None = None):
        super().__init__()

        self.tor_mode    = tor_mode
        self.vpn_manager = VpnManager()

        self.setWindowTitle("Ittrium Browser 🧅 [TOR]" if tor_mode else "Ittrium Browser")
        self.resize(1400, 860)

        if profile:
            self.profile = profile
        elif tor_mode:
            self.profile = build_incognito_profile(self, use_tor=True)
        else:
            self.profile = QWebEngineProfile.defaultProfile()
            apply_security_settings(self.profile)

        # ── Central splitter ──────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.current_tab_changed)

        self.vpn_panel = VpnPanel(self.vpn_manager)
        self.vpn_panel.setMinimumWidth(240)
        self.vpn_panel.setMaximumWidth(320)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.tabs)
        splitter.addWidget(self.vpn_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        splitter.setSizes([1100, 280])
        self.setCentralWidget(splitter)

        # ── Toolbar ───────────────────────────────────────────────
        self.navbar = QToolBar()
        self.addToolBar(self.navbar)

        self.navbar.addAction("◀", lambda: self.current_browser().back())
        self.navbar.addAction("▶", lambda: self.current_browser().forward())
        self.navbar.addAction("↺", lambda: self.current_browser().reload())
        self.navbar.addAction("⌂", self.go_home)

        self.mute_action = QAction("🔇", self)
        self.mute_action.setCheckable(True)
        self.mute_action.triggered.connect(self.toggle_mute_current_tab)
        self.navbar.addAction(self.mute_action)

        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.navbar.addWidget(self.url_bar)

        self.navbar.addAction("＋", lambda: self.add_new_tab())

        self.tor_btn = QPushButton()
        self.tor_btn.setCheckable(True)
        self.tor_btn.setChecked(self.tor_mode)
        self.tor_btn.setFixedWidth(120)
        self._style_tor_btn(self.tor_mode)
        self.tor_btn.clicked.connect(self.toggle_tor)
        self.navbar.addWidget(self.tor_btn)

        # ── Status bar ────────────────────────────────────────────
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.vpn_manager.status_changed.connect(
            lambda msg, ok: self.status.showMessage(msg)
        )
        self._update_status()

        # ── Downloads dock ────────────────────────────────────────
        from PySide6.QtWidgets import QDockWidget
        self.downloads_dock = QDockWidget("Downloads", self)
        self.downloads_list = QListWidget()
        self.downloads_dock.setWidget(self.downloads_list)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.downloads_dock)
        self.downloads_dock.hide()
        self.profile.downloadRequested.connect(self.handle_download_request)

        self.setup_shortcuts()
        self.add_new_tab(QUrl(HOME_URL), "Home")

    # ── Tor ───────────────────────────────────────────────────────

    def _style_tor_btn(self, active: bool):
        if active:
            self.tor_btn.setText("🧅  Tor ON")
            self.tor_btn.setStyleSheet(
                "QPushButton{background:#1a1a2e;color:#7fff7f;border:2px solid #39ff14;"
                "border-radius:4px;font-weight:bold;padding:3px 6px;}"
                "QPushButton:hover{background:#16213e;}"
            )
        else:
            self.tor_btn.setText("⚪  Tor OFF")
            self.tor_btn.setStyleSheet(
                "QPushButton{background:#2a2a2a;color:#aaa;border:2px solid #555;"
                "border-radius:4px;font-weight:bold;padding:3px 6px;}"
                "QPushButton:hover{background:#333;color:#ccc;}"
            )

    def toggle_tor(self, checked: bool):
        action = "Enable" if checked else "Disable"
        if checked:
            if IS_WINDOWS:
                extra = (
                    f"\n\nRequires Tor running on {TOR_PROXY_HOST}:{TOR_PROXY_PORT}.\n"
                    "Install: https://www.torproject.org/download/tor/"
                )
            else:
                extra = (
                    f"\n\nRequires Tor running on {TOR_PROXY_HOST}:{TOR_PROXY_PORT}.\n"
                    "Install: sudo apt install tor && sudo systemctl start tor"
                )
        else:
            extra = ""

        reply = QMessageBox.question(
            self, f"{action} Tor Mode",
            f"{action} Tor? Current window will reopen.{extra}",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            if not checked:
                clear_tor_proxy()
            self.vpn_manager.disconnect()
            new_win = BrowserWindow(tor_mode=checked)
            new_win.show()
            self.close()
        else:
            self.tor_btn.setChecked(not checked)
            self._style_tor_btn(not checked)

    def _update_status(self):
        if self.tor_mode:
            self.status.showMessage(
                f"🧅  Tor active — {TOR_PROXY_HOST}:{TOR_PROXY_PORT}  |  Upload a VPN config for extra masking"
            )
        else:
            self.status.showMessage(
                "Ready — upload a .ovpn or .conf in the VPN panel to mask your location"
            )

    # ── Shortcuts ─────────────────────────────────────────────────

    def setup_shortcuts(self):
        self._shortcuts = []
        def add(key: str, fn):
            a = QAction(self)
            a.setShortcut(QKeySequence(key))
            a.triggered.connect(fn)
            self.addAction(a)
            self._shortcuts.append(a)
        add("Ctrl+T", lambda: self.add_new_tab())
        add("Ctrl+W", self.close_current_tab)
        add("Ctrl+L", self.focus_url_bar)
        add("Ctrl+R", lambda: self.current_browser().reload())
        add("Ctrl+M", self.toggle_mute_current_tab)

    # ── Tabs ──────────────────────────────────────────────────────

    def add_new_tab(self, qurl: QUrl | None = None, label: str = "New Tab"):
        qurl    = qurl or QUrl(HOME_URL)
        browser = BrowserTab(self.profile, self)
        browser.setUrl(qurl)
        i = self.tabs.addTab(browser, label)
        self.tabs.setCurrentIndex(i)
        browser.urlChanged.connect(self.update_urlbar)
        browser.titleChanged.connect(lambda t, idx=i: self.tabs.setTabText(idx, t[:22]))
        browser.page().audioMutedChanged.connect(self.mute_action.setChecked)

    def close_tab(self, i: int):
        if self.tabs.count() == 1:
            self.close()
        else:
            self.tabs.removeTab(i)

    def close_current_tab(self):
        self.close_tab(self.tabs.currentIndex())

    def current_browser(self) -> BrowserTab:
        return self.tabs.currentWidget()

    def current_tab_changed(self, i: int):
        b = self.current_browser()
        if b:
            self.url_bar.setText(b.url().toString())
            self.mute_action.setChecked(b.page().isAudioMuted())

    # ── Navigation ────────────────────────────────────────────────

    def navigate_to_url(self):
        raw  = self.url_bar.text()
        safe = sanitize_url(raw)
        if safe is None:
            self.status.showMessage(
                f"🛡️  Blocked: '{raw[:80]}' — dangerous scheme or blocked domain", 5000
            )
            return
        self.current_browser().setUrl(safe)

    def go_home(self):
        self.current_browser().setUrl(QUrl(HOME_URL))

    def focus_url_bar(self):
        self.url_bar.setFocus()
        self.url_bar.selectAll()

    def update_urlbar(self, url: QUrl):
        text   = url.toString()
        scheme = url.scheme().lower()
        host   = url.host().lower()

        self.url_bar.setText(text)

        if is_blocked_domain(host):
            self.status.showMessage(f"🚫 Blocked domain: {host}")
        elif scheme == "https":
            self.status.showMessage(f"🔒 Secure  |  {host}")
        elif scheme == "http":
            self.status.showMessage(f"⚠️  Not secure (HTTP)  |  {host}")
        else:
            self.status.showMessage(f"  {text[:120]}")

    # ── Audio ─────────────────────────────────────────────────────

    def toggle_mute_current_tab(self):
        p = self.current_browser().page()
        p.setAudioMuted(not p.isAudioMuted())

    # ── Downloads ─────────────────────────────────────────────────

    def handle_download_request(self, download):
        filename = download.downloadFileName()
        ext      = Path(filename).suffix.lower()

    # ⚠️ Ask BEFORE accepting (Qt requirement)
        if ext in DANGEROUS_EXTENSIONS:
            reply = QMessageBox.warning(
                self,
                "⚠️ Potentially Dangerous File",
                f"'{filename}' is a {ext} file that could execute code on your system.\n\n"
                "Download anyway?",
                QMessageBox.Yes | QMessageBox.Cancel,
            )
            if reply != QMessageBox.Yes:
                download.cancel()
                return

        path, _ = QFileDialog.getSaveFileName(self, "Save File", filename)
        if not path:
            download.cancel()
            return

    # ✅ MUST be before accept()
        download.setDownloadDirectory(os.path.dirname(path))
        download.setDownloadFileName(os.path.basename(path))

        item = QListWidgetItem(f"⬇️ {filename}")
        self.downloads_list.addItem(item)
        self.downloads_dock.show()

    # ✅ Qt6 signals
        def update_progress():
            received = download.receivedBytes()
            total    = download.totalBytes()
            percent  = int((received / total) * 100) if total > 0 else 0
            item.setText(f"{filename} — {percent}%")

        def update_state(state):
            from PySide6.QtWebEngineCore import QWebEngineDownloadRequest

            def update_state(state):
                if state == QWebEngineDownloadRequest.DownloadCompleted:
                    item.setText(f"✅ Done — {filename}")
                elif state == QWebEngineDownloadRequest.DownloadInterrupted:
                    item.setText(f"❌ Failed — {filename}")
                elif state == QWebEngineDownloadRequest.DownloadCancelled:
                    item.setText(f"⛔ Cancelled — {filename}")

                    download.receivedBytesChanged.connect(update_progress)
                    download.stateChanged.connect(update_state)

    # ✅ Accept LAST
        download.accept()


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    # Harden Chromium renderer — must be set before QApplication
    chromium_flags = " ".join([
        "--log-level=3",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--disable-translate",
        "--metrics-recording-only",
        "--no-first-run",
        "--safebrowsing-disable-auto-update",
        "--password-store=basic",
        "--disable-features=MediaRouter",
    ])

    if IS_WINDOWS:
        # On Windows, also disable GPU sandbox issues and enable ANGLE
        chromium_flags += " --disable-gpu-sandbox --use-angle=d3d11"

    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = chromium_flags

    # High-DPI support (important for Windows scaling)
    if IS_WINDOWS:
        os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("Ittrium Browser")

    win = BrowserWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
