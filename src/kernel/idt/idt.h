/*
 * IntentKernel — IDT header
 */
#ifndef IK_IDT_H
#define IK_IDT_H

#include <stdint.h>

/* CPU register snapshot passed to every interrupt/exception handler */
typedef struct {
    uint32_t ds;                                          /* saved by stub  */
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;    /* pusha          */
    uint32_t int_no, err_code;                           /* pushed by stub */
    uint32_t eip, cs, eflags, useresp, ss;               /* pushed by CPU  */
} __attribute__((packed)) registers_t;

/* Handler function type */
typedef void (*isr_handler_t)(registers_t *regs);

/*
 * Register a C handler for interrupt vector n (0–255).
 * The previous handler (if any) is silently replaced.
 */
void idt_register_handler(uint8_t n, isr_handler_t handler);

/* Initialise and load the IDT */
void idt_init(void);

#endif /* IK_IDT_H */
