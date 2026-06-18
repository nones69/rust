/*
 * IntentKernel — GDT header
 * Provides the minimal 3-entry flat-memory GDT required to run the
 * kernel in 32-bit protected mode.
 */
#ifndef IK_GDT_H
#define IK_GDT_H

#include <stdint.h>

/* Segment selectors (byte offsets into the GDT) */
#define GDT_NULL_SEG   0x00
#define GDT_CODE_SEG   0x08
#define GDT_DATA_SEG   0x10

/* Initialise and load the GDT */
void gdt_init(void);

#endif /* IK_GDT_H */
