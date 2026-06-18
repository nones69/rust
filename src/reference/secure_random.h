/*
 * IntentKernel Secure Random Number Generator
 *
 * Portable interface to the host's cryptographically secure RNG.
 * Production kernels must use a hardware-backed entropy source.
 */

#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <stddef.h>

/**
 * Fill `buf` with `len` cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure.
 */
int secure_random(void *buf, size_t len);

#endif /* SECURE_RANDOM_H */
