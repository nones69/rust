# ikrl-sdk

Nine IntentKernel Relief Layer primitives.

## Status (honest)

| Backend | Feature | Maturity |
|---------|---------|----------|
| **IntentOS in-process** | `intentos` (default) | Working prototype — mint / verify / register / dispatch / default-deny |
| Legacy daemon RPC | `remote` | Compatibility with `intentd` / `eventscope` — not the happy path |

This crate does **not** provide host-wide file/network interception. That is Stages 1–2 overlay work.

## Quick start

```rust
use ikrl_sdk::IntentOsRuntime;
use std::time::Duration;

let sdk = IntentOsRuntime::boot("app").unwrap();
sdk.draw(b"frame").unwrap();
let tok = sdk.get_resource("file", "read").unwrap();
sdk.invoke_capability(&tok, "read", "notes.txt", &[]).unwrap();
sdk.exit(0).unwrap();
```

```bash
cd rust
cargo test -p ikrl-sdk
```
