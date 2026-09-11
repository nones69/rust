/* Linker script for the rust-os bare-metal kernel.
   Target: x86_64 ELF, loaded at 1 MiB (0x100000) by the bootloader.
   Dan — All-In-One ISO Build System v1.0.0                          */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start32)

SECTIONS {

    . = 0x100000;

    .boot :
    {
        KEEP(*(.multiboot2_header))
    }

    .text32 :
    {
        *(.text32)
        *(.text32.*)
    }

    .text :
    {
        *(.text)
        *(.text.*)
    }

    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data :
    {
        *(.data)
        *(.data.*)
    }

    .bss :
    {
        _bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.note.GNU-stack)
        *(.comment)
    }
}