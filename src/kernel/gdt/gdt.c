/*
 * IntentKernel — GDT implementation
 *
 * Sets up a minimal 3-entry flat-memory GDT:
 *   0x00  null descriptor
 *   0x08  kernel code  (ring 0, execute/read, 32-bit, 4 KB granularity)
 *   0x10  kernel data  (ring 0, read/write,   32-bit, 4 KB granularity)
 */
#include "gdt.h"
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Structures                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;       /* present | dpl | S | type                 */
    uint8_t  gran;         /* granularity | size | long | avl | limit_hi*/
    uint8_t  base_high;
} __attribute__((packed)) gdt_entry_t;

typedef struct {
    uint16_t limit;        /* size of GDT in bytes - 1                  */
    uint32_t base;         /* physical base address of GDT              */
} __attribute__((packed)) gdt_ptr_t;

/* ------------------------------------------------------------------ */
/* GDT storage                                                         */
/* ------------------------------------------------------------------ */

static gdt_entry_t gdt_entries[3];
static gdt_ptr_t   gdt_ptr;

/* ------------------------------------------------------------------ */
/* Assembly helper (defined in gdt_flush.asm)                          */
/* ------------------------------------------------------------------ */

extern void gdt_flush(uint32_t gdt_ptr_addr);

/* ------------------------------------------------------------------ */
/* Private helpers                                                     */
/* ------------------------------------------------------------------ */

static void gdt_set_gate(int idx,
                         uint32_t base,
                         uint32_t limit,
                         uint8_t  access,
                         uint8_t  gran) {
    gdt_entries[idx].base_low  = (uint16_t)(base & 0xFFFF);
    gdt_entries[idx].base_mid  = (uint8_t)((base >> 16) & 0xFF);
    gdt_entries[idx].base_high = (uint8_t)((base >> 24) & 0xFF);

    gdt_entries[idx].limit_low = (uint16_t)(limit & 0xFFFF);
    gdt_entries[idx].gran      = (uint8_t)((gran & 0xF0) |
                                           ((limit >> 16) & 0x0F));
    gdt_entries[idx].access    = access;
}

/* ------------------------------------------------------------------ */
/* Public interface                                                    */
/* ------------------------------------------------------------------ */

void gdt_init(void) {
    gdt_ptr.limit = (uint16_t)(sizeof(gdt_entries) - 1);
    gdt_ptr.base  = (uint32_t)&gdt_entries;

    /* 0: null descriptor */
    gdt_set_gate(0, 0, 0, 0x00, 0x00);

    /*
     * 1: kernel code segment
     *    base=0, limit=4 GB (0xFFFFF in 4KB granularity)
     *    access: present(1) | DPL=0 | S=1 | type=1010 (execute/read)
     *    gran:   G=1 | D/B=1 (32-bit) | L=0 | AVL=0
     */
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);

    /*
     * 2: kernel data segment
     *    access: present(1) | DPL=0 | S=1 | type=0010 (read/write)
     */
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);

    gdt_flush((uint32_t)&gdt_ptr);
}
