# ── All-In-One ISO Build System — Global Configuration ──────────────────────────
# All tunables for the build system. Override on the command line:
#   make iso ISO_VERSION=2.0.0 QEMU_MEM=4096
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

# ── Project Identity ──────────────────────────────────────────────────────────
ISO_NAME        := custom-os
ISO_VERSION     := 1.0.0
ISO_VOLID       := CUSTOM_OS_2026
AUTHOR          := Dan

# ── Architecture ──────────────────────────────────────────────────────────────
ARCH            := x86_64

# ── Rust OS Module ────────────────────────────────────────────────────────────
RUST_TARGET     := x86_64-unknown-none
RUST_PROFILE    := release
RUST_BUILD_FLAGS := -Z build-std=core,compiler_builtins \
                    -Z build-std-features=compiler-builtins-mem

# ── Ubuntu Live Module ────────────────────────────────────────────────────────
UBUNTU_RELEASE  := noble
UBUNTU_ARCH     := amd64
UBUNTU_MIRROR   := http://archive.ubuntu.com/ubuntu/

# ── Bootloader ────────────────────────────────────────────────────────────────
GRUB_THEME      := custom
GRUB_TIMEOUT    := 10
GRUB_DEFAULT    := 0

# ── Paths ─────────────────────────────────────────────────────────────────────
BUILD_DIR       := $(CURDIR)/build
DIST_DIR        := $(CURDIR)/dist
STAGE_DIR       := $(BUILD_DIR)/iso
RUST_BUILD_DIR  := $(BUILD_DIR)/rust-os
LIVE_BUILD_DIR  := $(BUILD_DIR)/ubuntu-live

# ── Output Artifact ───────────────────────────────────────────────────────────
ISO_OUTPUT      := $(DIST_DIR)/$(ISO_NAME).iso
CHECKSUM_FILE   := $(DIST_DIR)/$(ISO_NAME).iso.sha256

# ── QEMU Testing ──────────────────────────────────────────────────────────────
QEMU            := qemu-system-x86_64
QEMU_MEM        := 2048
QEMU_CORES      := 2
QEMU_ACCEL      := kvm:tcg
OVMF_PATH       := /usr/share/OVMF/OVMF_CODE.fd

# ── Tool Overrides ────────────────────────────────────────────────────────────
XORRISO         := xorriso
MKSQUASHFS      := mksquashfs
GRUB_MKSTANDALONE := grub-mkstandalone
