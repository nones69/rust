# All-In-One ISO Build System

Engineering Reference Manual v1.0.0 — multi-module pipeline producing `dist/custom-os.iso`.

| Module | Purpose |
|--------|---------|
| **rust-os** | Bare-metal Multiboot2 kernel (x86_64, no_std) |
| **ubuntu-live** | Ubuntu 24.04 Noble live session via `live-build` |
| **bootloader** | GRUB2 (UEFI) + ISOLINUX (BIOS), 5 menu entries |
| **iso-assembly** | `xorriso` hybrid ISO assembly + verification |

## Quick start (Ubuntu 24.04 host)

```bash
sudo bash scripts/bootstrap-host.sh
source ~/.cargo/env
make help
make all          # full pipeline (~30–90 min first run)
make verify
make qemu         # BIOS test
make qemu-uefi    # UEFI test
```

## Individual targets

```bash
make rust-os        # Module 1 only
sudo make ubuntu-live   # Module 2 (root required)
make bootloader     # Module 3
make iso            # Module 4
```

## Live session defaults

| Setting | Value |
|---------|-------|
| Hostname | `custom-os` |
| User | `liveuser` |
| Password | `live` |
| Volume ID | `CUSTOM_OS_2026` |

## Post-build squashfs edits

After `make ubuntu-live`, modify the live rootfs without a full rebuild:

```bash
sudo bash ubuntu-live/scripts/customize-rootfs.sh
```

## CI/CD

GitHub Actions workflow: `.github/workflows/iso-build.yml` (monorepo root, `working-directory: iso-build`).

## Documentation

Full manual: Engineering Reference Manual v1.0.0 (July 2026, Dan).