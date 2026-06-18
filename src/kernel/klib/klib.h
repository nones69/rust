/*
 * IntentKernel — Kernel string and memory library
 * Replaces the standard C library in the freestanding kernel environment.
 */
#ifndef IK_KLIB_H
#define IK_KLIB_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* Memory operations */
void *kmemset(void *dest, int c, size_t n);
void *kmemcpy(void *dest, const void *src, size_t n);
void *kmemmove(void *dest, const void *src, size_t n);
int   kmemcmp(const void *a, const void *b, size_t n);

/* String operations */
size_t kstrlen(const char *s);
int    kstrcmp(const char *a, const char *b);
int    kstrncmp(const char *a, const char *b, size_t n);
char  *kstrcpy(char *dest, const char *src);
char  *kstrncpy(char *dest, const char *src, size_t n);
char  *kstrchr(const char *s, int c);

/* Number → string conversion */
void  kitoa(int32_t n, char *buf, int base);
void  kutoa(uint32_t n, char *buf, int base);

/* Simple formatted output to a fixed buffer */
int   ksnprintf(char *buf, size_t size, const char *fmt, ...);
int   kvsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

/* String → integer */
int32_t  katoi(const char *s);
uint32_t katou(const char *s);

#endif /* IK_KLIB_H */
