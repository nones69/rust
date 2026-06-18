/*
 * IntentKernel Secure Random Number Generator — Host Reference
 *
 * Provides cryptographically secure random bytes using the best source
 * available on the host operating system:
 *   - Linux:    getrandom(2)
 *   - Windows:  BCryptGenRandom
 *   - Fallback: /dev/urandom
 *
 * This is the host-compiled reference implementation used by the test
 * harness. A native kernel must call the platform TRNG directly.
 */

#include "secure_random.h"

#if defined(__linux__)
#include <sys/random.h>
int secure_random(void *buf, size_t len) {
    return (int)getrandom(buf, len, 0) == (int)len ? 0 : -1;
}

#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
int secure_random(void *buf, size_t len) {
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
               ? 0
               : -1;
}

#else
#include <stdio.h>
int secure_random(void *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}
#endif
