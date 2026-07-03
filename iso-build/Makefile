# ── All-In-One ISO Build System — Top-Level Makefile ────────────────────────────
# GNU Make 4.3+ required. Run `make help` for usage.
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

# Include global configuration (overridable via command line)
include config.mk

# ── ANSI colour codes for terminal output ─────────────────────────────────────
BOLD   := \033[1m
RESET  := \033[0m
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
CYAN   := \033[0;36m

define banner
	@echo ""
	@echo -e "$(BOLD)$(BLUE)══════════════════════════════════════════════════════$(RESET)"
	@echo -e "$(BOLD)$(BLUE)  $(1)$(RESET)"
	@echo -e "$(BOLD)$(BLUE)══════════════════════════════════════════════════════$(RESET)"
	@echo ""
endef

# ── Phony Targets (never correspond to actual files) ─────────────────────────
.PHONY: all rust-os ubuntu-live bootloader iso-stage iso verify \
        qemu qemu-uefi qemu-serial clean distclean help \
        check-tools sign publish

# ── Default Target ────────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

# ── all: Full build pipeline ──────────────────────────────────────────────────
all: rust-os ubuntu-live bootloader iso
	$(call banner,All-In-One ISO Build Complete!)
	@echo -e "  Output: $(GREEN)$(ISO_OUTPUT)$(RESET)"
	@echo -e "  Size:   $$(du -h $(ISO_OUTPUT) | cut -f1)"
	@echo ""

# ── check-tools: Verify all required host tools are installed ─────────────────
check-tools:
	$(call banner,Checking Host Prerequisites ...)
	@for tool in cargo xorriso mksquashfs unsquashfs grub-mkstandalone \
	             lb debootstrap isohybrid qemu-system-x86_64 git make; do \
	    if command -v $$tool >/dev/null 2>&1; then \
	        echo -e "  $(GREEN)[OK]$(RESET)  $$tool ($$($$tool --version 2>&1 | head -1 || echo 'version unknown'))"; \
	    else \
	        echo -e "  $(RED)[MISSING]$(RESET)  $$tool — run: scripts/bootstrap-host.sh"; \
	    fi; \
	done
	@echo ""

# ── rust-os: Build the bare-metal Rust OS kernel ─────────────────────────────
rust-os: check-tools
	$(call banner,Module 1: Building Rust OS Kernel ...)
	@mkdir -p $(RUST_BUILD_DIR)
	@cd rust-os && cargo +nightly build \
	    --$(RUST_PROFILE) \
	    --target $(RUST_TARGET) \
	    $(RUST_BUILD_FLAGS) \
	    2>&1
	@cp rust-os/target/$(RUST_TARGET)/$(RUST_PROFILE)/rust-os \
	    $(RUST_BUILD_DIR)/rust-os.elf
	@echo -e "  $(GREEN)[OK]$(RESET) Kernel: $(RUST_BUILD_DIR)/rust-os.elf"
	@echo -e "  Size: $$(du -h $(RUST_BUILD_DIR)/rust-os.elf | cut -f1)"

# ── ubuntu-live: Run the Ubuntu live-build pipeline ──────────────────────────
ubuntu-live: check-tools
	$(call banner,Module 2: Building Ubuntu Live Layer ...)
	@echo -e "  $(YELLOW)[WARN]$(RESET) This step requires root (sudo). Estimated time: 20-60 min."
	@mkdir -p $(LIVE_BUILD_DIR)
	@cd ubuntu-live && sudo bash scripts/build-live.sh
	@echo -e "  $(GREEN)[OK]$(RESET) Live artifacts in: $(LIVE_BUILD_DIR)/"

# ── bootloader: Build GRUB EFI image and stage SYSLINUX ──────────────────────
bootloader: check-tools
	$(call banner,Module 3: Assembling Bootloader ...)
	@mkdir -p bootloader/efi/boot
	@$(GRUB_MKSTANDALONE) \
	    --format=x86_64-efi \
	    --output=bootloader/efi/boot/bootx64.efi \
	    --compress=xz \
	    --modules="part_gpt part_msdos iso9660 all_video gfxterm gfxmenu \
	               png search multiboot2 normal boot linux chain reboot echo" \
	    "boot/grub/grub.cfg=bootloader/grub/grub.cfg"
	@echo -e "  $(GREEN)[OK]$(RESET) EFI binary: bootloader/efi/boot/bootx64.efi"
	@echo -e "  Size: $$(du -h bootloader/efi/boot/bootx64.efi | cut -f1)"

# ── iso-stage: Prepare the ISO staging directory ──────────────────────────────
iso-stage: rust-os ubuntu-live bootloader
	$(call banner,Module 4: Staging ISO Filesystem ...)
	@mkdir -p $(STAGE_DIR)/{live,boot/grub/themes/custom,boot/grub/locale,isolinux,EFI/boot}
	@cp $(RUST_BUILD_DIR)/rust-os.elf    $(STAGE_DIR)/boot/
	@cp $(LIVE_BUILD_DIR)/filesystem.squashfs $(STAGE_DIR)/live/
	@cp $(LIVE_BUILD_DIR)/vmlinuz        $(STAGE_DIR)/live/
	@cp $(LIVE_BUILD_DIR)/initrd         $(STAGE_DIR)/live/
	@cp bootloader/grub/grub.cfg         $(STAGE_DIR)/boot/grub/
	@cp -r bootloader/grub/themes/custom/. $(STAGE_DIR)/boot/grub/themes/custom/
	@cp bootloader/syslinux/isolinux.cfg $(STAGE_DIR)/isolinux/
	@cp bootloader/efi/boot/bootx64.efi  $(STAGE_DIR)/EFI/boot/
	@for mod in ldlinux.c32 libcom32.c32 libutil.c32 vesamenu.c32; do \
	    cp /usr/lib/syslinux/modules/bios/$$mod $(STAGE_DIR)/isolinux/; \
	done
	@cp /usr/lib/ISOLINUX/isolinux.bin $(STAGE_DIR)/isolinux/
	@echo -e "  $(GREEN)[OK]$(RESET) Staging complete: $(STAGE_DIR)"

# ── iso: Produce the final hybrid ISO image ───────────────────────────────────
iso: iso-stage
	$(call banner,Module 4: Building Final ISO ...)
	@mkdir -p $(DIST_DIR)
	@bash iso-assembly/scripts/assemble.sh
	@echo -e "  $(GREEN)[OK]$(RESET) ISO: $(ISO_OUTPUT)"
	@echo -e "  Size: $$(du -h $(ISO_OUTPUT) | cut -f1)"

# ── verify: Verify ISO integrity ─────────────────────────────────────────────
verify:
	$(call banner,Verifying ISO ...)
	@[[ -f "$(ISO_OUTPUT)" ]] || \
	    { echo -e "  $(RED)[ERROR]$(RESET) ISO not found. Run 'make iso' first."; exit 1; }
	@bash iso-assembly/scripts/verify.sh

# ── qemu: Boot ISO in QEMU (BIOS mode) ───────────────────────────────────────
qemu: verify
	$(call banner,Launching QEMU — BIOS Boot Test ...)
	@echo -e "  $(YELLOW)[INFO]$(RESET) RAM: $(QEMU_MEM)M | Cores: $(QEMU_CORES) | Accel: $(QEMU_ACCEL)"
	@echo -e "  Press Ctrl+C or close the window to stop QEMU."
	@echo ""
	$(QEMU) \
	    -cdrom   $(ISO_OUTPUT)       \
	    -m       $(QEMU_MEM)M        \
	    -smp     $(QEMU_CORES)       \
	    -machine pc,accel=$(QEMU_ACCEL) \
	    -vga     std                 \
	    -serial  stdio               \
	    -display gtk                 \
	    -boot    d

# ── qemu-uefi: Boot ISO in QEMU with OVMF (UEFI mode) ───────────────────────
qemu-uefi: verify
	$(call banner,Launching QEMU — UEFI Boot Test (OVMF) ...)
	@[[ -f "$(OVMF_PATH)" ]] || \
	    { echo -e "  $(RED)[ERROR]$(RESET) OVMF not found at $(OVMF_PATH). Run: apt install ovmf"; exit 1; }
	@echo -e "  $(YELLOW)[INFO]$(RESET) UEFI firmware: $(OVMF_PATH)"
	$(QEMU) \
	    -cdrom   $(ISO_OUTPUT)           \
	    -m       $(QEMU_MEM)M            \
	    -smp     $(QEMU_CORES)           \
	    -machine q35,accel=$(QEMU_ACCEL) \
	    -bios    $(OVMF_PATH)            \
	    -vga     std                     \
	    -serial  stdio                   \
	    -display gtk                     \
	    -boot    d

# ── clean: Remove all generated build artifacts ───────────────────────────────
clean:
	$(call banner,Cleaning Build Artifacts ...)
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -rf rust-os/target/
	@echo -e "  $(GREEN)[OK]$(RESET) build/ and dist/ removed"

# ── distclean: Deep clean including live-build cache ─────────────────────────
distclean: clean
	$(call banner,Deep Clean — Removing live-build Cache ...)
	@cd ubuntu-live && sudo lb clean --purge 2>/dev/null || true
	@echo -e "  $(GREEN)[OK]$(RESET) live-build cache purged"

# ── sign: GPG-sign the ISO and create checksum file ──────────────────────────
sign:
	$(call banner,Signing ISO ...)
	@[[ -f "$(ISO_OUTPUT)" ]] || \
	    { echo -e "  $(RED)[ERROR]$(RESET) ISO not found. Run 'make iso' first."; exit 1; }
	sha256sum $(ISO_OUTPUT) > $(CHECKSUM_FILE)
	gpg --armor --detach-sign --output $(ISO_OUTPUT).asc $(ISO_OUTPUT)
	@echo -e "  $(GREEN)[OK]$(RESET) Signature: $(ISO_OUTPUT).asc"
	@echo -e "  $(GREEN)[OK]$(RESET) Checksums: $(CHECKSUM_FILE)"

# ── publish: Create a GitHub Release with the ISO artifact ───────────────────
publish: sign
	$(call banner,Publishing GitHub Release ...)
	@command -v gh >/dev/null || \
	    { echo -e "  $(RED)[ERROR]$(RESET) GitHub CLI (gh) not found: apt install gh"; exit 1; }
	gh release create \
	    "v$(ISO_VERSION)" \
	    $(ISO_OUTPUT) \
	    $(ISO_OUTPUT).asc \
	    $(CHECKSUM_FILE) \
	    --title "Custom OS v$(ISO_VERSION) — All-In-One ISO Build System" \
	    --notes "Automated release by Dan — $(shell date -u '+%Y-%m-%d %H:%M UTC')"
	@echo -e "  $(GREEN)[OK]$(RESET) Release published: v$(ISO_VERSION)"

# ── help: Print usage table ───────────────────────────────────────────────────
help:
	@echo ""
	@echo -e "$(BOLD)$(CYAN)  All-In-One ISO Build System v$(ISO_VERSION)$(RESET)"
	@echo -e "$(CYAN)  Author: $(AUTHOR) | Target: $(ARCH) | Ubuntu: $(UBUNTU_RELEASE)$(RESET)"
	@echo ""
	@echo -e "$(BOLD)  Usage: make [target] [VARIABLE=value ...]$(RESET)"
	@echo ""
	@echo -e "$(BOLD)  Build Targets:$(RESET)"
	@echo -e "    $(GREEN)all$(RESET)           Run the full pipeline: rust-os → ubuntu-live → bootloader → iso"
	@echo -e "    $(GREEN)rust-os$(RESET)       Build the bare-metal Rust OS kernel (Module 1)"
	@echo -e "    $(GREEN)ubuntu-live$(RESET)   Build the Ubuntu 24.04 live layer via live-build (Module 2)"
	@echo -e "    $(GREEN)bootloader$(RESET)    Build GRUB EFI image and stage SYSLINUX (Module 3)"
	@echo -e "    $(GREEN)iso-stage$(RESET)     Prepare the ISO staging directory (Module 4, step 1)"
	@echo -e "    $(GREEN)iso$(RESET)           Assemble the final hybrid ISO (Module 4, step 2)"
	@echo ""
	@echo -e "$(BOLD)  Verification & Testing:$(RESET)"
	@echo -e "    $(GREEN)verify$(RESET)        Verify ISO integrity (format, checksum, El Torito)"
	@echo -e "    $(GREEN)qemu$(RESET)          Boot ISO in QEMU (BIOS/legacy mode)"
	@echo -e "    $(GREEN)qemu-uefi$(RESET)     Boot ISO in QEMU with OVMF (UEFI mode)"
	@echo ""
	@echo -e "$(BOLD)  Maintenance:$(RESET)"
	@echo -e "    $(GREEN)check-tools$(RESET)   Verify all required host tools are present"
	@echo -e "    $(GREEN)clean$(RESET)         Remove build/ and dist/ directories"
	@echo -e "    $(GREEN)distclean$(RESET)     Deep clean: also purges live-build cache (slow to rebuild)"
	@echo ""
	@echo -e "$(BOLD)  Distribution:$(RESET)"
	@echo -e "    $(GREEN)sign$(RESET)          GPG-sign the ISO and generate sha256 checksum"
	@echo -e "    $(GREEN)publish$(RESET)       Create a GitHub Release with the ISO (requires: gh, gpg)"
	@echo ""
	@echo -e "$(BOLD)  Key Variables (override on command line):$(RESET)"
	@echo -e "    ISO_VERSION=$(ISO_VERSION)   QEMU_MEM=$(QEMU_MEM)   QEMU_CORES=$(QEMU_CORES)"
	@echo -e "    UBUNTU_RELEASE=$(UBUNTU_RELEASE)    RUST_TARGET=$(RUST_TARGET)"
	@echo ""
