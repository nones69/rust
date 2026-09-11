/* IntentKernel Stage-2 LSM stub header — not a shippable module.
 * Prototype contract only; kernel build is out of scope for Linux CI.
 */
#ifndef INTENTKERNEL_IK_LSM_H
#define INTENTKERNEL_IK_LSM_H

#include <linux/types.h>

/* Userspace-presented capability id (JTI hash / handle). */
struct ik_cap_ref {
	__u8 jti[16];
	__u32 generation;
};

enum ik_hook_kind {
	IK_HOOK_FILE_OPEN = 1,
	IK_HOOK_SOCKET_CONNECT = 2,
	IK_HOOK_BPRM_CHECK = 3,
};

/* Return 0 allow, -EPERM deny (illustrative). */
int ik_overlay_check(enum ik_hook_kind hook, const struct ik_cap_ref *cap,
		     const char *target);

#endif /* INTENTKERNEL_IK_LSM_H */
