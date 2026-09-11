# LSM stub (Stage 2 scaffold)

Headers and notes for a future out-of-tree LSM that would call into a
userspace IntentOS broker. **Does not build a kernel module in CI.**

Intended hooks (names illustrative): `ik_file_open`, `ik_socket_connect`,
`ik_bprm_check`.

See [`../../../docs/overlay/stage2-linux-lsm.md`](../../../docs/overlay/stage2-linux-lsm.md).
