#ifndef INTENTKERNEL_CONSOLE_H
#define INTENTKERNEL_CONSOLE_H

#include <stddef.h>
#include <stdint.h>

void console_init(void);
void console_putchar(char c);
void console_write(const char* data, size_t size);
void console_writestring(const char* data);

#endif