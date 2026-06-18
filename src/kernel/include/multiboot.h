/*
 * IntentKernel — Multiboot 1 information structures
 * Reference: https://www.gnu.org/software/grub/manual/multiboot/multiboot.html
 */
#ifndef IK_MULTIBOOT_H
#define IK_MULTIBOOT_H

#include <stdint.h>

/* Magic value placed in EAX by the bootloader */
#define MULTIBOOT_BOOTLOADER_MAGIC  0x2BADB002U

/* Flags in multiboot_info_t.flags indicating which fields are valid */
#define MULTIBOOT_INFO_MEMORY       (1U << 0)
#define MULTIBOOT_INFO_BOOTDEV      (1U << 1)
#define MULTIBOOT_INFO_CMDLINE      (1U << 2)
#define MULTIBOOT_INFO_MODS         (1U << 3)
#define MULTIBOOT_INFO_MEM_MAP      (1U << 6)

/* Memory-map entry types */
#define MULTIBOOT_MEMORY_AVAILABLE  1
#define MULTIBOOT_MEMORY_RESERVED   2

/* ------------------------------------------------------------------ */
/* Multiboot information structure passed in EBX                       */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t flags;
    uint32_t mem_lower;       /* KB of lower memory (below 1 MB)       */
    uint32_t mem_upper;       /* KB of upper memory (above 1 MB)       */
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint8_t  syms[16];
    uint32_t mmap_length;     /* bytes in memory map                   */
    uint32_t mmap_addr;       /* physical address of memory map        */
    uint32_t drives_length;
    uint32_t drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
    uint32_t apm_table;
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
} __attribute__((packed)) multiboot_info_t;

/* ------------------------------------------------------------------ */
/* Memory-map entry (variable-size; size field precedes the struct)    */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t size;            /* size of this entry (not including size itself) */
    uint64_t addr;            /* base physical address                  */
    uint64_t len;             /* length in bytes                        */
    uint32_t type;            /* MULTIBOOT_MEMORY_* constant            */
} __attribute__((packed)) multiboot_mmap_entry_t;

#endif /* IK_MULTIBOOT_H */
