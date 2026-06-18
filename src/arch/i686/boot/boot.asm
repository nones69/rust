; IntentKernel — Multiboot1 Bootstrap
; Targets: i686 32-bit protected mode, ELF32
; Loaded by GRUB (or any Multiboot-compliant bootloader).

; -------------------------------------------------------------------------
; Multiboot 1 header constants
; -------------------------------------------------------------------------
MULTIBOOT_MAGIC    equ  0x1BADB002
MULTIBOOT_FLAGS    equ  0x00000000     ; no special flags
MULTIBOOT_CHECKSUM equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

; -------------------------------------------------------------------------
; Multiboot header — must be within first 8 KB of the kernel image
; -------------------------------------------------------------------------
section .multiboot
align 4
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM

; -------------------------------------------------------------------------
; Bootstrap stack (32 KB, 16-byte aligned)
; -------------------------------------------------------------------------
section .bss
align 16
stack_bottom:
    resb 32768
stack_top:

; -------------------------------------------------------------------------
; Kernel entry point
; -------------------------------------------------------------------------
section .text
global _start
extern kmain

_start:
    ; Set up the stack
    mov  esp, stack_top

    ; Clear EFLAGS
    push 0
    popf

    ; Push arguments for kmain(uint32_t magic, uint32_t mb_info_addr)
    ; EAX = Multiboot magic, EBX = pointer to multiboot_info_t
    push ebx        ; mb_info_addr
    push eax        ; mb_magic

    call kmain

    ; Should never return — halt forever
    cli
.hang:
    hlt
    jmp .hang
