# IntentOS — Universal Cross-Platform Upgrade Layer

**Add AI-powered security, communication, and intelligence to any device — without replacing anything.**

---

## What This Is

IntentOS IKRL (IntentKernel Relief Layer) is a non-destructive upgrade package that installs *alongside* your existing operating system.  It adds capability-secured AI features, real-time security monitoring, and communication tools while leaving every existing app, file, document, and setting completely untouched.

| Platform   | Package Type          | Min Version           | Install Time |
|:-----------|:----------------------|:----------------------|:-------------|
| Linux      | Shell + systemd       | Any modern distro     | ~2 minutes   |
| Windows    | PowerShell installer  | Windows 10 / 11       | ~3 minutes   |
| Android    | APK sideload          | Android 8.0 (API 26)  | ~1 minute    |
| ChromeOS   | Chrome Extension      | Chrome 100+           | ~30 seconds  |
| VMware     | ISO boot entry        | VMware Workstation 16+ | ~2 minutes  |

---

## Quick Start

### Linux
```bash
curl -fsSL https://raw.githubusercontent.com/intentos/install/main/linux/install.sh | bash
# OR, offline:
chmod +x install/linux/install.sh
sudo bash install/linux/install.sh
```

**To upgrade an existing installation:**
```bash
chmod +x install/linux/upgrade.sh
sudo bash install/linux/upgrade.sh
```

### Windows (PowerShell — run as Administrator)
```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\install\windows\install.ps1
```

### Android
1. Enable **Unknown Sources** in Settings → Security
2. Transfer `IntentOS.apk` to the device
3. Tap the APK and install
4. Open IntentOS and tap **Start Service**

### ChromeOS / Chrome
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `install/chromeos/` folder
4. Pin the IntentOS extension to your toolbar

### VMware
1. Boot the Custom OS ISO in VMware Workstation / Fusion / ESXi
2. At the boot menu, select **Custom OS — VMware Optimized Live Session**
3. Once the live session has loaded, open a terminal and run:
   ```bash
   sudo bash /media/cdrom/install/linux/install.sh
   ```
   Or use the **Install Custom OS to Disk** boot entry for a guided disk installation.

---

## What Gets Installed

```
IntentOS Upgrade Layer
├── Core daemon          (Python service, runs in background)
├── Control Surface      (Web UI at http://localhost:5000)
├── AI Integration       (Capability-gated agent pipeline)
├── Security Monitor     (Real-time threat detection)
├── Privacy Guard        (Permission and data-access alerts)
└── Communication Tools  (Message/call organisation)
```

## What Is NEVER Touched

- ✅ All existing applications
- ✅ All user files, documents, photos
- ✅ All system settings and preferences
- ✅ All user accounts and profiles
- ✅ All network and hardware configuration

---

## Upgrading

### Linux
```bash
sudo bash install/linux/upgrade.sh
```
The upgrade script backs up your configuration, fetches the latest application files, upgrades Python dependencies, and restarts the service — leaving all user data and settings untouched.

---

## Uninstalling

### Linux
```bash
sudo bash install/linux/uninstall.sh
```

### Windows
```powershell
.\install\windows\uninstall.ps1
```

### Android
Settings → Apps → IntentOS → Uninstall

### ChromeOS
chrome://extensions → IntentOS → Remove

---

## Architecture

```
┌──────────────────────────────────────────────┐
│           USER'S EXISTING SYSTEM             │
│  (Apps / Files / Settings — NEVER MODIFIED)  │
├──────────────────────────────────────────────┤
│           IntentOS Upgrade Layer             │
│  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Core Daemon │  │   Control Surface    │  │
│  │  (port 5000) │  │   Web UI / Android   │  │
│  └──────┬───────┘  └──────────────────────┘  │
│         │                                     │
│  ┌──────▼─────────────────────────────────┐  │
│  │           Agent Pipeline               │  │
│  │  Strategist → Analyst → Indexer →      │  │
│  │  Executor  (all capability-gated)      │  │
│  └────────────────────────────────────────┘  │
│  ┌───────────────┐  ┌──────────────────────┐ │
│  │ Security Mon. │  │  Privacy Guard       │ │
│  └───────────────┘  └──────────────────────┘ │
└──────────────────────────────────────────────┘
```

---

## Security Model

IntentOS uses the **IntentKernel capability model** — every AI action requires an explicit,
time-limited capability token.  No action can be performed silently or without user intent.

See [`docs/intentkernel_thesis.md`](../docs/intentkernel_thesis.md) for the full specification.

---

## License

Apache 2.0 — see [`LICENSE`](../LICENSE)
