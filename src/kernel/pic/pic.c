/*
 * IntentKernel — 8259A PIC driver
 *
 * Remaps the two PIC chips so that hardware IRQs 0-7 fire on
 * interrupt vectors 32-39 and IRQs 8-15 fire on vectors 40-47,
 * keeping them clear of the CPU exception range (0-31).
 */
#include "pic.h"
#include "../io/io.h"
#include "../idt/idt.h"

/* I/O ports */
#define PIC1_CMD   0x20
#define PIC1_DATA  0x21
#define PIC2_CMD   0xA0
#define PIC2_DATA  0xA1

/* Initialisation control words */
#define ICW1_INIT  0x11   /* begin init sequence, expects ICW4          */
#define ICW4_8086  0x01   /* 8086/88 mode                               */

/* End-of-interrupt */
#define PIC_EOI    0x20

void pic_init(void) {
    /* Save current masks */
    uint8_t mask1 = inb(PIC1_DATA);
    uint8_t mask2 = inb(PIC2_DATA);

    /* Start initialisation sequence (cascade mode) */
    outb(PIC1_CMD,  ICW1_INIT); io_wait();
    outb(PIC2_CMD,  ICW1_INIT); io_wait();

    /* ICW2: vector offsets */
    outb(PIC1_DATA, PIC_IRQ_BASE_MASTER); io_wait();  /* IRQ0-7  → 32-39  */
    outb(PIC2_DATA, PIC_IRQ_BASE_SLAVE);  io_wait();  /* IRQ8-15 → 40-47  */

    /* ICW3: cascading */
    outb(PIC1_DATA, 0x04); io_wait();  /* slave attached on IRQ2           */
    outb(PIC2_DATA, 0x02); io_wait();  /* slave identity = 2               */

    /* ICW4: 8086 mode */
    outb(PIC1_DATA, ICW4_8086); io_wait();
    outb(PIC2_DATA, ICW4_8086); io_wait();

    /* Restore saved masks */
    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);
}

void pic_eoi(uint8_t irq) {
    if (irq >= 8) {
        outb(PIC2_CMD, PIC_EOI);  /* notify slave first                  */
    }
    outb(PIC1_CMD, PIC_EOI);
}

void pic_mask(uint8_t irq) {
    uint16_t port;
    if (irq < 8) { port = PIC1_DATA; }
    else         { port = PIC2_DATA; irq = (uint8_t)(irq - 8); }
    uint8_t val = inb(port) | (uint8_t)(1 << irq);
    outb(port, val);
}

void pic_unmask(uint8_t irq) {
    uint16_t port;
    if (irq < 8) { port = PIC1_DATA; }
    else         { port = PIC2_DATA; irq = (uint8_t)(irq - 8); }
    uint8_t val = inb(port) & (uint8_t)(~(1 << irq));
    outb(port, val);
}

/* ------------------------------------------------------------------ */
/* IRQ dispatcher — called from the assembly IRQ common stub           */
/* ------------------------------------------------------------------ */

/* Forward declarations for registered IRQ handlers */
static isr_handler_t irq_handlers[16];

void irq_register(uint8_t irq, isr_handler_t fn) {
    if (irq < 16) irq_handlers[irq] = fn;
}

/* Called from idt.c → irq_common_stub */
void irq_handler(registers_t *regs) {
    uint8_t irq = (uint8_t)(regs->int_no - PIC_IRQ_BASE_MASTER);

    /* Ignore spurious IRQ 7 (master) and IRQ 15 (slave) */
    if (irq == 7) {
        uint8_t isr_val = inb(PIC1_CMD | 0x03);  /* read ISR              */
        if (!(isr_val & 0x80)) return;
    }
    if (irq == 15) {
        uint8_t isr_val = inb(PIC2_CMD | 0x03);
        if (!(isr_val & 0x80)) {
            outb(PIC1_CMD, PIC_EOI);  /* still need master EOI            */
            return;
        }
    }

    if (irq < 16 && irq_handlers[irq]) {
        irq_handlers[irq](regs);
    }

    pic_eoi(irq);
}
