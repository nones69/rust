ENTRY(_start)

SECTIONS
{
    /* Begin putting sections at 1 Megabyte, a conventional place for kernels to be loaded at by the bootloader. */
    . = 1M;

    /* Multiboot header must be early in the image. */
    .text : ALIGN(4K)
    {
        *(.multiboot)
        *(.text)
    }

    /* Read-only data. */
    .rodata : ALIGN(4K)
    {
        *(.rodata)
    }

    /* Read-write data (initialized) */
    .data : ALIGN(4K)
    {
        *(.data)
    }

    /* Read-write data (uninitialized) and stack */
    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss)
    }
}
