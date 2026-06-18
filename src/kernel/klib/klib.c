/*
 * IntentKernel — Kernel string and memory library implementation
 */
#include "klib.h"

/* ------------------------------------------------------------------ */
/* Memory operations                                                   */
/* ------------------------------------------------------------------ */

void *kmemset(void *dest, int c, size_t n) {
    uint8_t *p = (uint8_t *)dest;
    uint8_t  v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) p[i] = v;
    return dest;
}

void *kmemcpy(void *dest, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dest;
}

void *kmemmove(void *dest, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    if (d < s) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    } else if (d > s) {
        for (size_t i = n; i > 0; i--) d[i-1] = s[i-1];
    }
    return dest;
}

int kmemcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++) {
        if (x[i] < y[i]) return -1;
        if (x[i] > y[i]) return  1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* String operations                                                   */
/* ------------------------------------------------------------------ */

size_t kstrlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int kstrcmp(const char *a, const char *b) {
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int kstrncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

char *kstrcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

char *kstrncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) dest[i] = src[i];
    for (; i < n; i++) dest[i] = '\0';
    return dest;
}

char *kstrchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return (c == '\0') ? (char *)s : (char *)0;
}

/* ------------------------------------------------------------------ */
/* Number → string conversion                                          */
/* ------------------------------------------------------------------ */

static const char digits[] = "0123456789abcdef";

void kitoa(int32_t n, char *buf, int base) {
    char  tmp[34];
    int   i = 0;
    int   neg = 0;
    uint32_t u;

    if (base < 2 || base > 16) { buf[0] = '\0'; return; }

    if (n < 0 && base == 10) {
        neg = 1;
        u = (uint32_t)(-(n + 1)) + 1U;  /* handles INT32_MIN safely */
    } else {
        u = (uint32_t)n;
    }

    if (u == 0) { tmp[i++] = '0'; }
    else { while (u) { tmp[i++] = digits[u % (uint32_t)base]; u /= (uint32_t)base; } }

    if (neg) tmp[i++] = '-';

    /* reverse */
    int j = 0;
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = '\0';
}

void kutoa(uint32_t n, char *buf, int base) {
    char tmp[34];
    int  i = 0;

    if (base < 2 || base > 16) { buf[0] = '\0'; return; }

    if (n == 0) { buf[0] = '0'; buf[1] = '\0'; return; }

    while (n) { tmp[i++] = digits[n % (uint32_t)base]; n /= (uint32_t)base; }

    int j = 0;
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = '\0';
}

/* ------------------------------------------------------------------ */
/* kvsnprintf — minimal printf-style formatter                         */
/* Supported: %d %i %u %x %X %s %c %p %%                              */
/* Width and zero-padding: %08x, %5d etc.                              */
/* ------------------------------------------------------------------ */

int kvsnprintf(char *buf, size_t size, const char *fmt, va_list ap) {
    size_t pos = 0;
    char   tmp[34];

    if (size == 0) return 0;

#define EMIT(ch) do { if (pos + 1 < size) buf[pos++] = (ch); } while(0)

    while (*fmt) {
        if (*fmt != '%') { EMIT(*fmt++); continue; }
        fmt++;  /* skip '%' */

        /* Flags */
        int zero_pad = 0;
        if (*fmt == '0') { zero_pad = 1; fmt++; }

        /* Width */
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt++ - '0');
        }

        char spec = *fmt++;
        switch (spec) {
        case 'd': case 'i': {
            int32_t v = va_arg(ap, int32_t);
            kitoa(v, tmp, 10);
            int len = (int)kstrlen(tmp);
            char pad = zero_pad ? '0' : ' ';
            for (int p = len; p < width; p++) EMIT(pad);
            for (int k = 0; tmp[k]; k++) EMIT(tmp[k]);
            break;
        }
        case 'u': {
            uint32_t v = va_arg(ap, uint32_t);
            kutoa(v, tmp, 10);
            int len = (int)kstrlen(tmp);
            char pad = zero_pad ? '0' : ' ';
            for (int p = len; p < width; p++) EMIT(pad);
            for (int k = 0; tmp[k]; k++) EMIT(tmp[k]);
            break;
        }
        case 'x': {
            uint32_t v = va_arg(ap, uint32_t);
            kutoa(v, tmp, 16);
            int len = (int)kstrlen(tmp);
            char pad = zero_pad ? '0' : ' ';
            for (int p = len; p < width; p++) EMIT(pad);
            for (int k = 0; tmp[k]; k++) EMIT(tmp[k]);
            break;
        }
        case 'X': {
            uint32_t v = va_arg(ap, uint32_t);
            kutoa(v, tmp, 16);
            /* uppercase */
            for (int k = 0; tmp[k]; k++)
                if (tmp[k] >= 'a' && tmp[k] <= 'f') tmp[k] -= 32;
            int len = (int)kstrlen(tmp);
            char pad = zero_pad ? '0' : ' ';
            for (int p = len; p < width; p++) EMIT(pad);
            for (int k = 0; tmp[k]; k++) EMIT(tmp[k]);
            break;
        }
        case 'p': {
            uint32_t v = (uint32_t)(uintptr_t)va_arg(ap, void *);
            kutoa(v, tmp, 16);
            EMIT('0'); EMIT('x');
            int len = (int)kstrlen(tmp);
            for (int p = len; p < 8; p++) EMIT('0');
            for (int k = 0; tmp[k]; k++) EMIT(tmp[k]);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            int len = (int)kstrlen(s);
            char pad = zero_pad ? '0' : ' ';
            for (int p = len; p < width; p++) EMIT(pad);
            while (*s) EMIT(*s++);
            break;
        }
        case 'c':
            EMIT((char)va_arg(ap, int));
            break;
        case '%':
            EMIT('%');
            break;
        default:
            EMIT('%'); EMIT(spec);
            break;
        }
    }

#undef EMIT

    buf[pos] = '\0';
    return (int)pos;
}

int ksnprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = kvsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return r;
}

/* ------------------------------------------------------------------ */
/* String → integer                                                    */
/* ------------------------------------------------------------------ */

int32_t katoi(const char *s) {
    int32_t n = 0;
    int     neg = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (*s++ - '0');
    }
    return neg ? -n : n;
}

uint32_t katou(const char *s) {
    uint32_t n = 0;
    while (*s == ' ' || *s == '\t') s++;
    /* allow 0x prefix for hex */
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        while ((*s >= '0' && *s <= '9') ||
               (*s >= 'a' && *s <= 'f') ||
               (*s >= 'A' && *s <= 'F')) {
            uint8_t d;
            if (*s >= '0' && *s <= '9') d = (uint8_t)(*s - '0');
            else if (*s >= 'a' && *s <= 'f') d = (uint8_t)(*s - 'a' + 10);
            else d = (uint8_t)(*s - 'A' + 10);
            n = n * 16 + d;
            s++;
        }
    } else {
        while (*s >= '0' && *s <= '9') n = n * 10 + (uint8_t)(*s++ - '0');
    }
    return n;
}
