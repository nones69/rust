/*
 * IntentKernel — IDT implementation
 */
#include "idt.h"
#include "../klib/klib.h"

/* ------------------------------------------------------------------ */
/* Structures                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t offset_lo;  /* lower 16 bits of handler address  */
    uint16_t selector;   /* code segment selector             */
    uint8_t  zero;       /* always 0                          */
    uint8_t  type_attr;  /* gate type, dpl, present flag      */
    uint16_t offset_hi;  /* upper 16 bits of handler address  */
} __attribute__((packed)) idt_gate_t;

typedef struct {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed)) idt_ptr_t;

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

static idt_gate_t    idt_gates[256];
static idt_ptr_t     idt_ptr;
static isr_handler_t handlers[256];

/* ------------------------------------------------------------------ */
/* Assembly helpers declared in isr.asm                               */
/* ------------------------------------------------------------------ */

extern void isr0(void);  extern void isr1(void);  extern void isr2(void);
extern void isr3(void);  extern void isr4(void);  extern void isr5(void);
extern void isr6(void);  extern void isr7(void);  extern void isr8(void);
extern void isr9(void);  extern void isr10(void); extern void isr11(void);
extern void isr12(void); extern void isr13(void); extern void isr14(void);
extern void isr15(void); extern void isr16(void); extern void isr17(void);
extern void isr18(void); extern void isr19(void); extern void isr20(void);
extern void isr21(void); extern void isr22(void); extern void isr23(void);
extern void isr24(void); extern void isr25(void); extern void isr26(void);
extern void isr27(void); extern void isr28(void); extern void isr29(void);
extern void isr30(void); extern void isr31(void);

extern void irq0(void);  extern void irq1(void);  extern void irq2(void);
extern void irq3(void);  extern void irq4(void);  extern void irq5(void);
extern void irq6(void);  extern void irq7(void);  extern void irq8(void);
extern void irq9(void);  extern void irq10(void); extern void irq11(void);
extern void irq12(void); extern void irq13(void); extern void irq14(void);
extern void irq15(void);

/* ------------------------------------------------------------------ */
/* Private helpers                                                     */
/* ------------------------------------------------------------------ */

static void idt_set_gate(uint8_t n, uint32_t handler, uint16_t sel,
                          uint8_t flags) {
    idt_gates[n].offset_lo = (uint16_t)(handler & 0xFFFF);
    idt_gates[n].offset_hi = (uint16_t)((handler >> 16) & 0xFFFF);
    idt_gates[n].selector  = sel;
    idt_gates[n].zero      = 0;
    idt_gates[n].type_attr = flags;
}

static void lidt(idt_ptr_t *ptr) {
    __asm__ __volatile__("lidt (%0)" : : "r"(ptr));
}

/* Default exception handler — prints a panic message */
static void default_exception_handler(registers_t *regs) {
    static const char *exceptions[] = {
        "Divide-by-zero",       "Debug",               "NMI",
        "Breakpoint",           "Overflow",            "Bound range exceeded",
        "Invalid opcode",       "Device not available","Double fault",
        "Coprocessor seg overrun","Invalid TSS",       "Segment not present",
        "Stack fault",          "General protection",  "Page fault",
        "Reserved",             "x87 FPU error",       "Alignment check",
        "Machine check",        "SIMD FP exception",   "Virtualisation",
        "Reserved","Reserved","Reserved","Reserved","Reserved",
        "Reserved","Reserved","Reserved","Reserved",   "Security exception",
        "Reserved"
    };
    const char *name = (regs->int_no < 32) ? exceptions[regs->int_no]
                                            : "Unknown";

    /* Minimal panic: write directly to VGA memory */
    volatile uint16_t *vga = (volatile uint16_t *)0xB8000;
    const char *msg = "*** KERNEL EXCEPTION: ";
    uint8_t color = 0x4F; /* white on red */
    int col = 0;

    /* Clear first line */
    for (int i = 0; i < 80; i++) vga[i] = (uint16_t)(' ' | ((uint16_t)color << 8));

    for (int i = 0; msg[i] && col < 80; i++)
        vga[col++] = (uint16_t)(msg[i] | ((uint16_t)color << 8));

    for (int i = 0; name[i] && col < 80; i++)
        vga[col++] = (uint16_t)(name[i] | ((uint16_t)color << 8));

    /* Halt */
    __asm__ __volatile__("cli; hlt");
    while (1) {}
    (void)regs;
}

/* ------------------------------------------------------------------ */
/* Public interface                                                    */
/* ------------------------------------------------------------------ */

void idt_register_handler(uint8_t n, isr_handler_t handler) {
    handlers[n] = handler;
}

/* Called from the common ISR trampoline */
void isr_handler(registers_t *regs) {
    if (handlers[regs->int_no]) {
        handlers[regs->int_no](regs);
    } else {
        default_exception_handler(regs);
    }
}

/* Called from the common IRQ trampoline — defined in pic.c */
void irq_handler(registers_t *regs);

void idt_init(void) {
    kmemset(&idt_gates, 0, sizeof(idt_gates));
    kmemset(&handlers,  0, sizeof(handlers));

    idt_ptr.limit = (uint16_t)(sizeof(idt_gates) - 1);
    idt_ptr.base  = (uint32_t)&idt_gates;

    /* 0x8E = present | DPL=0 | 32-bit interrupt gate */
    uint8_t flags = 0x8E;

    idt_set_gate( 0, (uint32_t)isr0,  0x08, flags);
    idt_set_gate( 1, (uint32_t)isr1,  0x08, flags);
    idt_set_gate( 2, (uint32_t)isr2,  0x08, flags);
    idt_set_gate( 3, (uint32_t)isr3,  0x08, flags);
    idt_set_gate( 4, (uint32_t)isr4,  0x08, flags);
    idt_set_gate( 5, (uint32_t)isr5,  0x08, flags);
    idt_set_gate( 6, (uint32_t)isr6,  0x08, flags);
    idt_set_gate( 7, (uint32_t)isr7,  0x08, flags);
    idt_set_gate( 8, (uint32_t)isr8,  0x08, flags);
    idt_set_gate( 9, (uint32_t)isr9,  0x08, flags);
    idt_set_gate(10, (uint32_t)isr10, 0x08, flags);
    idt_set_gate(11, (uint32_t)isr11, 0x08, flags);
    idt_set_gate(12, (uint32_t)isr12, 0x08, flags);
    idt_set_gate(13, (uint32_t)isr13, 0x08, flags);
    idt_set_gate(14, (uint32_t)isr14, 0x08, flags);
    idt_set_gate(15, (uint32_t)isr15, 0x08, flags);
    idt_set_gate(16, (uint32_t)isr16, 0x08, flags);
    idt_set_gate(17, (uint32_t)isr17, 0x08, flags);
    idt_set_gate(18, (uint32_t)isr18, 0x08, flags);
    idt_set_gate(19, (uint32_t)isr19, 0x08, flags);
    idt_set_gate(20, (uint32_t)isr20, 0x08, flags);
    idt_set_gate(21, (uint32_t)isr21, 0x08, flags);
    idt_set_gate(22, (uint32_t)isr22, 0x08, flags);
    idt_set_gate(23, (uint32_t)isr23, 0x08, flags);
    idt_set_gate(24, (uint32_t)isr24, 0x08, flags);
    idt_set_gate(25, (uint32_t)isr25, 0x08, flags);
    idt_set_gate(26, (uint32_t)isr26, 0x08, flags);
    idt_set_gate(27, (uint32_t)isr27, 0x08, flags);
    idt_set_gate(28, (uint32_t)isr28, 0x08, flags);
    idt_set_gate(29, (uint32_t)isr29, 0x08, flags);
    idt_set_gate(30, (uint32_t)isr30, 0x08, flags);
    idt_set_gate(31, (uint32_t)isr31, 0x08, flags);

    idt_set_gate(32, (uint32_t)irq0,  0x08, flags);
    idt_set_gate(33, (uint32_t)irq1,  0x08, flags);
    idt_set_gate(34, (uint32_t)irq2,  0x08, flags);
    idt_set_gate(35, (uint32_t)irq3,  0x08, flags);
    idt_set_gate(36, (uint32_t)irq4,  0x08, flags);
    idt_set_gate(37, (uint32_t)irq5,  0x08, flags);
    idt_set_gate(38, (uint32_t)irq6,  0x08, flags);
    idt_set_gate(39, (uint32_t)irq7,  0x08, flags);
    idt_set_gate(40, (uint32_t)irq8,  0x08, flags);
    idt_set_gate(41, (uint32_t)irq9,  0x08, flags);
    idt_set_gate(42, (uint32_t)irq10, 0x08, flags);
    idt_set_gate(43, (uint32_t)irq11, 0x08, flags);
    idt_set_gate(44, (uint32_t)irq12, 0x08, flags);
    idt_set_gate(45, (uint32_t)irq13, 0x08, flags);
    idt_set_gate(46, (uint32_t)irq14, 0x08, flags);
    idt_set_gate(47, (uint32_t)irq15, 0x08, flags);

    lidt(&idt_ptr);
}
