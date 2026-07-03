    .set MULTIBOOT2_MAGIC,    0xe85250d6
    .set MULTIBOOT2_ARCH,     0
    .set HEADER_LENGTH,       (multiboot2_header_end - multiboot2_header_start)
    .set HEADER_CHECKSUM,     -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + HEADER_LENGTH)

    .section .multiboot2_header, "a"
    .align 8
multiboot2_header_start:
    .long  MULTIBOOT2_MAGIC
    .long  MULTIBOOT2_ARCH
    .long  HEADER_LENGTH
    .long  HEADER_CHECKSUM
    .short 0
    .short 0
    .long  8
multiboot2_header_end:

    .section .text
    .global _start32

_start32:
    jmp _start