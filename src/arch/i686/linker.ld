/*
 * IntentKernel — i686 Linker Script
 * Kernel is loaded at 1 MB (0x00100000) by the Multiboot bootloader.
 */

ENTRY(_start)

SECTIONS {
    /* ------------------------------------------------------------------ */
    /* Load at 1 MB — conventional Multiboot load address                 */
    /* ------------------------------------------------------------------ */
    . = 1M;

    /* Code + Multiboot header (header must be in the first 8 KB)         */
    .text BLOCK(4K) : ALIGN(4K) {
        *(.multiboot)
        *(.text)
    }

    /* Read-only data                                                       */
    .rodata BLOCK(4K) : ALIGN(4K) {
        *(.rodata)
    }

    /* Initialised read-write data                                         */
    .data BLOCK(4K) : ALIGN(4K) {
        *(.data)
    }

    /* Zero-initialised data + BSS                                         */
    .bss BLOCK(4K) : ALIGN(4K) {
        *(COMMON)
        *(.bss)
    }

    /* Export the end of the kernel image for the physical memory manager  */
    kernel_end = .;
}
