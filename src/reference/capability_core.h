#ifndef CAPABILITY_CORE_H
#define CAPABILITY_CORE_H

#include <stdint.h>

#define CAP_TABLE_SIZE   65536    /* Maximum concurrent capabilities    */
#define CAP_KEY_SIZE     32       /* 256-bit cryptographic key          */

/* Capability Structure */
struct Capability {
    uint8_t  key[CAP_KEY_SIZE];   /* Unforgeable random key             */
    uint64_t expires;             /* Absolute expiration timestamp      */
    uint32_t type;                /* Resource type identifier           */
    uint16_t uses;                /* Remaining use count                */
    uint16_t id;                  /* Table index                        */
} __attribute__((packed));

/* Global capability table (exposed for testing) */
extern struct Capability cap_table[CAP_TABLE_SIZE];

/* Monotonic clock provided by platform */
extern uint64_t get_time(void);

/* Core capability functions */
int capability_create(uint32_t type, uint64_t ttl, uint16_t uses);
int capability_validate(struct Capability *cap);
int capability_revoke(uint16_t id);

#endif /* CAPABILITY_CORE_H */