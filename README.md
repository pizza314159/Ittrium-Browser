# 🧭 ByteBrowser

**ByteBrowser** is an AI-assisted, privacy-focused web browser built with Python and Qt.  
It includes built-in support for VPN configuration files, Tor proxy mode, and multiple browser hardening features like tracker blocking, HTTPS enforcement, and fingerprinting mitigation.

---

## ⚡ Features

### 🌐 Browsing
- Tab-based browsing system
- DuckDuckGo as default search engine
- URL smart detection (auto HTTPS upgrade)
- Download manager with safety warnings

### 🔐 Privacy & Security
- HTTPS-only enforcement
- Tracker & malware domain blocking
- Certificate error blocking
- WebRTC leak protection
- Popup and redirect blocking
- Mixed content blocking
- URL scheme filtering (`file://`, `data:` blocked)
- Basic anti-fingerprinting scripts
- Chromium sandbox hardening flags

### 🧅 Tor Mode
- SOCKS5 proxy support (Tor network)
- One-click Tor toggle
- Requires local Tor service

### 🔒 VPN Support
- Upload `.ovpn` (OpenVPN) files
- Upload `.conf` (WireGuard) files
- Automatic connection handling
- IP change detection

---

## 🧰 Requirements

### System Requirements
- Python 3.10+
- Linux / Windows (Linux recommended for VPN/Tor features)

---

## 📦 Python Dependencies

Install required packages:

```bash
pip install PySide6 PySide6-Addons PySide6-Essentials
