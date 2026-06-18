/*
 * IntentKernel — x86 port I/O primitives
 * All functions are inlined to avoid function-call overhead on hot paths.
 */
#ifndef IK_IO_H
#define IK_IO_H

#include <stdint.h>

/* Write a byte to an I/O port */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ __volatile__("outb %0, %1" : : "a"(value), "Nd"(port));
}

/* Read a byte from an I/O port */
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ __volatile__("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

/* Write a word to an I/O port */
static inline void outw(uint16_t port, uint16_t value) {
    __asm__ __volatile__("outw %0, %1" : : "a"(value), "Nd"(port));
}

/* Read a word from an I/O port */
static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ __volatile__("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

/*
 * Small I/O delay — writes to port 0x80 (POST card port), which is safe
 * to use as a ~1 µs delay on most hardware.
 */
static inline void io_wait(void) {
    outb(0x80, 0);
}

/* Enable / disable hardware interrupts */
static inline void sti(void) {
    __asm__ __volatile__("sti");
}

static inline void cli(void) {
    __asm__ __volatile__("cli");
}

/* Halt the CPU until the next interrupt */
static inline void hlt(void) {
    __asm__ __volatile__("hlt");
}

#endif /* IK_IO_H */
