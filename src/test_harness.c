#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "reference/capability_core.h"
#include "reference/secure_random.h"

/* Windows-compatible time function */
uint64_t get_time(void) {
    #ifdef _WIN32
    /* Windows implementation */
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)(counter.QuadPart * 1000000000ULL / frequency.QuadPart);
    #else
    /* POSIX implementation */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    #endif
}

/* Secure random is provided by secure_random.c */

/* Test program */
int main() {
    printf("IntentKernel Capability System Test Harness\n");
    printf("==========================================\n\n");
    
    /* Create a capability for file access */
    int file_cap_id = capability_create(1, 5000000000ULL, 1); /* Type 1, 5s TTL, 1 use */
    if (file_cap_id < 0) {
        printf("Failed to create file capability\n");
        return 1;
    }
    printf("Created file capability with ID: %d\n", file_cap_id);
    
    /* Create a capability for network access */
    int net_cap_id = capability_create(2, 10000000000ULL, 3); /* Type 2, 10s TTL, 3 uses */
    if (net_cap_id < 0) {
        printf("Failed to create network capability\n");
        return 1;
    }
    printf("Created network capability with ID: %d\n", net_cap_id);
    
    /* Validate the file capability */
    struct Capability file_cap = cap_table[file_cap_id];
    int result = capability_validate(&file_cap);
    printf("File capability validation result: %d\n", result);
    
    /* Try to validate it again (should fail as it was single-use) */
    result = capability_validate(&file_cap);
    printf("Second validation attempt result: %d\n", result);
    
    /* Validate the network capability multiple times */
    struct Capability net_cap = cap_table[net_cap_id];
    printf("Network capability validation results:\n");
    for (int i = 0; i < 4; i++) {
        result = capability_validate(&net_cap);
        printf("  Attempt %d: %d\n", i+1, result);
    }
    
    /* Revoke the network capability */
    capability_revoke(net_cap_id);
    printf("Network capability revoked\n");
    
    /* Try to validate after revocation */
    result = capability_validate(&net_cap);
    printf("Validation after revocation: %d\n", result);
    
    printf("\nPress Enter to exit...");
    getchar();
    
    return 0;
}