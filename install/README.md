# IntentOS install scripts (experimental)

Non-destructive Linux installer/upgrader scripts that attempt to place an IntentOS
upgrade layer alongside an existing OS.

## Status

**Experimental / incomplete.** This checkout currently ships:

| Path | Status |
|------|--------|
| `linux/install.sh` | Present — review before running as root |
| `linux/upgrade.sh` | Present — review before running as root |
| Windows / Android / ChromeOS packages | **Not present** in this tree |

The IntentKernel capability model is implemented primarily by the Rust reference
runtime under [`../rust/`](../rust/). Do not read these installers as proof of
host-wide enforcement.

## Linux (manual)

```bash
chmod +x install/linux/install.sh
# Review the script, then:
# sudo bash install/linux/install.sh
```

Upgrade:

```bash
chmod +x install/linux/upgrade.sh
# sudo bash install/linux/upgrade.sh
```
