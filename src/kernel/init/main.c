#include "../console/console.h"

void kmain(void) {
    // Initialize the terminal driver
    console_init();

    // Print welcome messages
    console_writestring("IntentKernel v1.1.0 - Boot Stage 1 Successful!\n");
    console_writestring("VGA Terminal Driver Initialized.\n");

    // Halt the CPU
    while (1) {
        __asm__ __volatile__("hlt");
    }
}