/*
 * IntentKernel — PIC (8259A) header
 */
#ifndef IK_PIC_H
#define IK_PIC_H

#include <stdint.h>

/*
 * After pic_init() the IRQ-to-vector mapping is:
 *   IRQ 0–7  → INT 32–39
 *   IRQ 8–15 → INT 40–47
 */
#define PIC_IRQ_BASE_MASTER  32
#define PIC_IRQ_BASE_SLAVE   40

void    pic_init(void);
void    pic_eoi(uint8_t irq);        /* send End-Of-Interrupt for irq 0–15 */
void    pic_mask(uint8_t irq);       /* mask (disable) an IRQ line          */
void    pic_unmask(uint8_t irq);     /* unmask (enable) an IRQ line         */

#endif /* IK_PIC_H */
