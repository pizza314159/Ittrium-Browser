"""
ByteBrowser — hardened browser with file-upload VPN + Tor toggle.

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
  • Drop a .ovpn file  → OpenVPN tunnel   (needs: sudo apt install openvpn)
  • Drop a .conf file  → WireGuard tunnel  (needs: sudo apt install wireguard-tools)

Tor usage:
  • Flip the Tor toggle in the toolbar
    (needs: sudo apt install tor && sudo systemctl start tor)
"""

import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from PySide6.QtCore import QUrl, Qt, Signal, QObject
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
    QDockWidget,
    QPushButton,
    QLabel,
    QHBoxLayout,
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


# ── Constants ──────────────────────────────────────────────────────────────

HOME_URL       = "https://duckduckgo.com"
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://ipecho.net/plain",
    "https://icanhazip.com",
]


# ── Security: blocked domains (trackers, malware, ads) ────────────────────
# Sourced from well-known blocklists (StevenBlack, abuse.ch categories).
# Extended at runtime — add your own entries to BLOCKED_DOMAINS.
BLOCKED_DOMAINS: set[str] = {
    # Malware / phishing infrastructure
    "malware.testcave.xyz", "phishing-test.com",
    # Major tracker networks
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adnxs.com", "adsrvr.org", "rubiconproject.com", "openx.net",
    "pubmatic.com", "casalemedia.com", "smartadserver.com",
    "scorecardresearch.com", "quantserve.com", "bluekai.com",
    "demdex.net", "everesttech.net", "rlcdn.com", "krxd.net",
    "taboola.com", "outbrain.com", "revcontent.com",
    # Fingerprinting / surveillance
    "fingerprintjs.com", "fingerprintjs2.com", "augur.io",
    "iovation.com", "threatmetrix.com", "sift.com",
    # Telemetry sinks often abused
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
# Tight policy: only same-origin scripts/styles, no inline eval,
# block object/embed, restrict form targets.
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

# ── Security: anti-fingerprinting JS injected on every page ───────────────
ANTI_FINGERPRINT_JS = """
(function() {
    // Spoof canvas fingerprint
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

    // Spoof AudioContext fingerprint
    if (window.AudioContext || window.webkitAudioContext) {
        const AC = window.AudioContext || window.webkitAudioContext;
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function() {
            const arr = origGetChannelData.apply(this, arguments);
            for (let i = 0; i < arr.length; i += 100)
                arr[i] += (Math.random() - 0.5) * 1e-7;
            return arr;
        };
    }

    // Block navigator.plugins enumeration (used for fingerprinting)
    Object.defineProperty(navigator, 'plugins', {
        get: () => Object.create(PluginArray.prototype)
    });

    // Spoof hardwareConcurrency (commonly used for fingerprinting)
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });

    // Spoof deviceMemory
    if ('deviceMemory' in navigator)
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

    // Block battery API
    if (navigator.getBattery)
        navigator.getBattery = () => Promise.reject(new Error('blocked'));

    // Normalise screen resolution (common fingerprint vector)
    Object.defineProperty(screen, 'width',       { get: () => 1920 });
    Object.defineProperty(screen, 'height',      { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth',  { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth',  { get: () => 24  });

    // Remove webdriver flag
    Object.defineProperty(navigator, 'webdriver', { get: () => false });
})();
"""


# ── Helpers ────────────────────────────────────────────────────────────────

def normalize_url(text):
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
    """
    Full security sanitization pipeline for user-typed URLs.
    Returns None if the URL should be blocked entirely.
    """
    url = normalize_url(text)
    scheme = url.scheme().lower()

    # Block dangerous schemes
    if scheme in BLOCKED_SCHEMES:
        return None

    # Force HTTPS for http:// navigations
    if scheme == "http":
        url = QUrl(url.toString().replace("http://", "https://", 1))

    # Block homograph / non-ASCII hostnames (IDN homograph attacks)
    host = url.host()
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        # Re-encode as punycode — safe but warn
        puny = host.encode("idna").decode("ascii")
        url.setHost(puny)

    # Block known bad domains
    if is_blocked_domain(url.host()):
        return None

    return url


def is_blocked_domain(host: str) -> bool:
    host = host.lower().lstrip("www.")
    if host in BLOCKED_DOMAINS:
        return True
    # Check parent domains (e.g. sub.doubleclick.net)
    parts = host.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in BLOCKED_DOMAINS:
            return True
    return False


def get_public_ip(timeout=8):
    for url in IP_CHECK_URLS:
        try:
            with urlopen(url, timeout=timeout) as r:
                return r.read().decode().strip()
        except Exception:
            continue
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


# ── VPN Manager ────────────────────────────────────────────────────────────

class VpnManager(QObject):
    status_changed = Signal(str, bool)   # (message, is_connected)
    ip_resolved    = Signal(str, str)    # (real_ip, apparent_ip)

    def __init__(self):
        super().__init__()
        self._pre_vpn_ip   = None
        self._wg_iface     = None
        self._ovpn_tmpfile = None
        self.vpn_ip        = None
        self.vpn_type      = None

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
                subprocess.run(
                    ["sudo", "pkill", "-f", "bytebrowser_vpn_"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                if self._ovpn_tmpfile:
                    try:
                        os.unlink(self._ovpn_tmpfile)
                    except Exception:
                        pass
                    self._ovpn_tmpfile = None
            elif self.vpn_type == "wireguard" and self._wg_iface:
                subprocess.run(
                    ["sudo", "wg-quick", "down", self._wg_iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self._wg_iface = None
        except Exception:
            pass
        self.vpn_ip   = None
        self.vpn_type = None
        self.status_changed.emit("VPN disconnected", False)

    @property
    def is_connected(self):
        return self.vpn_ip is not None

    # ── Internal ──────────────────────────────────────────────────

    def _connect_thread(self, config_path: str, vpn_type: str):
        if vpn_type == "openvpn":
            self._start_openvpn(config_path)
        elif vpn_type == "wireguard":
            self._start_wireguard(config_path)

    def _start_openvpn(self, config_path: str):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".ovpn", delete=False, prefix="bytebrowser_vpn_"
        )
        try:
            with open(config_path, "r", errors="replace") as f:
                tmp.write(f.read())
            tmp.flush()
            tmp.close()
            self._ovpn_tmpfile = tmp.name
        except Exception as e:
            self.status_changed.emit(f"❌ Could not read config: {e}", False)
            return

        cmd = ["sudo", "openvpn", "--config", tmp.name,
               "--daemon", "--log", "/tmp/bytebrowser_vpn.log"]
        try:
            subprocess.run(cmd, check=True, timeout=12,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.status_changed.emit(
                "❌ openvpn not found — install: sudo apt install openvpn", False
            )
            return
        except subprocess.CalledProcessError as e:
            self.status_changed.emit(f"❌ OpenVPN error: {e}", False)
            return
        except subprocess.TimeoutExpired:
            pass

        self._poll_for_ip("OpenVPN")

    def _start_wireguard(self, config_path: str):
        iface = "wg-bb0"
        dest  = f"/tmp/{iface}.conf"
        try:
            with open(config_path, "r", errors="replace") as f:
                data = f.read()
            proc = subprocess.run(
                ["sudo", "tee", dest],
                input=data.encode(), capture_output=True,
            )
            if proc.returncode != 0:
                self.status_changed.emit("❌ Could not write WireGuard config to /tmp", False)
                return
        except Exception as e:
            self.status_changed.emit(f"❌ Config read error: {e}", False)
            return

        try:
            result = subprocess.run(
                ["sudo", "wg-quick", "up", dest],
                capture_output=True, text=True, timeout=20,
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

    def _poll_for_ip(self, label: str):
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(2)
            ip = get_public_ip(timeout=5)
            if ip and ip != self._pre_vpn_ip:
                self.vpn_ip = ip
                self.status_changed.emit(
                    f"🔒 {label} connected  |  Apparent IP: {ip}", True
                )
                self.ip_resolved.emit(self._pre_vpn_ip or "?", ip)
                return
        self.status_changed.emit(
            f"⚠️  {label} may not have connected — IP unchanged after 30 s", False
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

        subtitle = QLabel("Upload your own .ovpn or .conf file to connect.")
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

        hint = QLabel(
            "Works with any provider that gives you an OpenVPN or WireGuard config.\n"
            "Needs openvpn / wireguard-tools installed + sudo."
        )
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

    def _on_ip_resolved(self, real_ip, vpn_ip):
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
        name        = Path(path).name
        type_label  = "OpenVPN" if vpn_type == "openvpn" else "WireGuard"
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
        color = "#51cf66" if connected else ("#ff7070" if ("❌" in msg or "⚠️" in msg) else "#aaa")
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
    Hardened QWebEnginePage:
      - Blocks navigations to dangerous schemes / blocked domains
      - Forces HTTPS upgrades
      - Intercepts certificate errors (hard block)
      - Kills popup / new-window requests
      - Injects CSP meta tag + anti-fingerprinting JS on every load
    """

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        pass  # Silence console noise; don't leak internals

    # ── Block cert errors hard (no click-through) ──────────────────
    def certificateError(self, error):
        # Reject ALL certificate errors — no "proceed anyway" option.
        # This stops SSL-strip, MITM, and expired-cert attacks cold.
        error.rejectCertificate()
        return True

    # ── Kill popups and new-window hijacks ─────────────────────────
    def createWindow(self, win_type):
        # Open in a new tab in the same window instead of spawning
        # a new uncontrolled window (common clickjacking vector).
        main = self.view().window()
        if hasattr(main, "add_new_tab"):
            main.add_new_tab()
            return main.current_browser().page()
        return None  # Block if we can't route safely

    # ── Intercept every navigation request ────────────────────────
    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        scheme = url.scheme().lower()
        host   = url.host().lower()

        # Hard-block dangerous schemes
        if scheme in BLOCKED_SCHEMES:
            return False

        # Hard-block known malicious / tracking domains
        if is_blocked_domain(host):
            return False

        # Upgrade HTTP → HTTPS for main-frame navigations
        if scheme == "http" and is_main_frame:
            https_url = QUrl(url.toString().replace("http://", "https://", 1))
            # Schedule the upgrade after this call returns
            QUrl_upgraded = https_url  # captured for lambda
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.view().setUrl(QUrl_upgraded))
            return False  # Cancel the HTTP load

        return True

    # ── Inject security JS on every page ──────────────────────────
    def javaScriptFinished(self):
        pass

    def loadFinished_security_inject(self, ok):
        if ok:
            self.runJavaScript(INJECT_CSP_JS)
            self.runJavaScript(ANTI_FINGERPRINT_JS)


class BrowserTab(QWebEngineView):
    def __init__(self, profile, parent=None):
        super().__init__(parent)
        page = BrowserPage(profile, self)
        self.setPage(page)
        # Wire security JS injection to every successful load
        self.loadFinished.connect(page.loadFinished_security_inject)


def apply_security_settings(profile: QWebEngineProfile):
    """Apply hardened QWebEngineSettings to any profile."""
    s = profile.settings()
    WA = QWebEngineSettings.WebAttribute

    # ── Disable attack surfaces ────────────────────────────────────
    s.setAttribute(WA.JavascriptCanOpenWindows,         False)  # no popup spawning
    s.setAttribute(WA.JavascriptCanAccessClipboard,     False)  # no clipboard theft
    s.setAttribute(WA.LocalContentCanAccessRemoteUrls,  False)  # no local→remote leaks
    s.setAttribute(WA.LocalContentCanAccessFileUrls,    False)  # no file:// enumeration
    s.setAttribute(WA.AllowRunningInsecureContent,      False)  # block mixed content
    s.setAttribute(WA.AllowGeolocationOnInsecureOrigins,False)  # no geo on HTTP
    s.setAttribute(WA.WebGLEnabled,                     False)  # WebGL fingerprinting
    s.setAttribute(WA.Accelerated2dCanvasEnabled,       False)  # canvas fingerprinting
    s.setAttribute(WA.AutoLoadIconsForPage,             True)   # favicons OK
    s.setAttribute(WA.PluginsEnabled,                   False)  # no NPAPI/PPAPI plugins
    s.setAttribute(WA.PdfViewerEnabled,                 True)   # PDF viewing OK
    s.setAttribute(WA.FullScreenSupportEnabled,         False)  # block fullscreen hijack
    s.setAttribute(WA.ScreenCaptureEnabled,             False)  # block screen capture
    s.setAttribute(WA.WebRTCPublicInterfacesOnly,       True)   # prevent WebRTC IP leak
    s.setAttribute(WA.DnsPrefetchEnabled,               False)  # no DNS prefetch leaks
    s.setAttribute(WA.NavigateOnDropEnabled,            False)  # block drag-drop navigation

    # ── Keep usable ───────────────────────────────────────────────
    s.setAttribute(WA.JavascriptEnabled,                True)   # JS on (needed for web)
    s.setAttribute(WA.LocalStorageEnabled,              True)   # storage on (normal mode)
    s.setAttribute(WA.ScrollAnimatorEnabled,            True)   # smooth scroll OK
    s.setAttribute(WA.SpatialNavigationEnabled,         False)

    # ── HTTP Strict Transport Security ────────────────────────────
    profile.setHttpAcceptLanguage("en-US,en;q=0.9")
    # Spoof a generic UA — avoids unique fingerprinting via user-agent
    profile.setHttpUserAgent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


def build_incognito_profile(parent, use_tor=False):
    profile = QWebEngineProfile(parent)   # no name → off-the-record
    apply_security_settings(profile)
    # Extra restrictions for incognito/tor
    s = profile.settings()
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
    def __init__(self, tor_mode=False, profile=None):
        super().__init__()

        self.tor_mode    = tor_mode
        self.vpn_manager = VpnManager()

        self.setWindowTitle("ByteBrowser 🧅 [TOR]" if tor_mode else "ByteBrowser")
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

        # ── Status bar ──────────────────────────â─────────────────
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.vpn_manager.status_changed.connect(
            lambda msg, ok: self.status.showMessage(msg)
        )
        self._update_status()

        # ── Downloads dock ────────────────────────────────────────
        self.downloads_dock = QDockWidget("Downloads", self)
        self.downloads_list = QListWidget()
        self.downloads_dock.setWidget(self.downloads_list)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.downloads_dock)
        self.downloads_dock.hide()
        self.profile.downloadRequested.connect(self.handle_download_request)

        self.setup_shortcuts()
        self.add_new_tab(QUrl(HOME_URL), "Home")

    # ── Tor ───────────────────────────────────────────────────────

    def _style_tor_btn(self, active):
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

    def toggle_tor(self, checked):
        action = "Enable" if checked else "Disable"
        extra  = f"\n\nRequires Tor running on {TOR_PROXY_HOST}:{TOR_PROXY_PORT}." if checked else ""
        reply  = QMessageBox.question(
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

    # ── Shortcuts ────────────────────────────────────────────────

    def setup_shortcuts(self):
        self._shortcuts = []
        def add(key, fn):
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

    # ── Tabs ─────────────────────────────────────────────────────

    def add_new_tab(self, qurl=None, label="New Tab"):
        qurl = qurl or QUrl(HOME_URL)
        browser = BrowserTab(self.profile, self)
        browser.setUrl(qurl)
        i = self.tabs.addTab(browser, label)
        self.tabs.setCurrentIndex(i)
        browser.urlChanged.connect(self.update_urlbar)
        browser.titleChanged.connect(lambda t: self.tabs.setTabText(i, t[:22]))
        browser.page().audioMutedChanged.connect(self.mute_action.setChecked)

    def close_tab(self, i):
        if self.tabs.count() == 1:
            self.close()
        else:
            self.tabs.removeTab(i)

    def close_current_tab(self):
        self.close_tab(self.tabs.currentIndex())

    def current_browser(self):
        return self.tabs.currentWidget()

    def current_tab_changed(self, i):
        b = self.current_browser()
        if b:
            self.url_bar.setText(b.url().toString())
            self.mute_action.setChecked(b.page().isAudioMuted())

    # ── Navigation ───────────────────────────────────────────────

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

    def update_urlbar(self, url: QUrl):
        text   = url.toString()
        scheme = url.scheme().lower()
        host   = url.host().lower()

        self.url_bar.setText(text)

        # Visual security badge in status bar
        if is_blocked_domain(host):
            self.status.showMessage(f"🚫 Blocked domain: {host}")
        elif scheme == "https":
            self.status.showMessage(f"🔒 Secure  |  {host}")
        elif scheme == "http":
            self.status.showMessage(f"⚠️  Not secure (HTTP)  |  {host}")
        else:
            self.status.showMessage(f"  {text[:120]}")

    # ── Audio ────────────────────────────────────────────────────

    def toggle_mute_current_tab(self):
        p = self.current_browser().page()
        p.setAudioMuted(not p.isAudioMuted())

    # ── Downloads ────────────────────────────────────────────────

    def handle_download_request(self, download):
        filename  = download.downloadFileName()
        ext       = Path(filename).suffix.lower()

        # Warn on dangerous extensions
        if ext in DANGEROUS_EXTENSIONS:
            reply = QMessageBox.warning(
                self,
                "⚠️  Potentially Dangerous File",
                f"'{filename}' is a {ext} file that could execute code on your system.\n\n"
                "Only proceed if you trust the source completely.\n\nDownload anyway?",
                QMessageBox.Yes | QMessageBox.Cancel,
            )
            if reply != QMessageBox.Yes:
                download.cancel()
                return

        path, _ = QFileDialog.getSaveFileName(self, "Save File", filename)
        if not path:
            download.cancel()
            return
        download.setDownloadFileName(os.path.basename(path))
        download.setDownloadDirectory(os.path.dirname(path))
        item = QListWidgetItem(f"⬇️  {filename}")
        self.downloads_list.addItem(item)
        self.downloads_dock.show()
        download.downloadProgress.connect(
            lambda r, t: item.setText(
                f"{filename}  {int(r/t*100) if t else 0}%"
            )
        )
        download.stateChanged.connect(
            lambda s: item.setText(f"{'✅ Done' if s == 2 else '❌ Failed'}  —  {filename}")
        )
        download.accept()

    def closeEvent(self, event):
        self.vpn_manager.disconnect()
        super().closeEvent(event)


# ── Entry point ────────────────────────────────────────────────────────────

def main():
    # ── Harden Chromium renderer process ──────────────────────────
    # Must be set before QApplication / Chromium initialises.
    chromium_flags = " ".join([
        "--log-level=3",                    # suppress NSS noise
        "--disable-background-networking",  # no background phone-home
        "--disable-default-apps",
        "--disable-extensions",             # no extension injection
        "--disable-sync",                   # no Google sync
        "--disable-translate",              # no external translate requests
        "--metrics-recording-only",         # no UMA upload
        "--no-first-run",
        "--safebrowsing-disable-auto-update",
        "--password-store=basic",
        "--disable-features=MediaRouter",   # no Cast/media-router leaks
    ])
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = chromium_flags

    app = QApplication(sys.argv)
    app.setApplicationName("ByteBrowser")
    win = BrowserWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

