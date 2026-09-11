# Development mTLS PKI (prototype)

IntentKernel ships an **ephemeral development CA** helper in
`ikrl_transport::dev_pki::DevPki` for local labs and CI.

## What it is

- Generates a throwaway CA + server/client leaf certificates with `rcgen`
- Writes PEM files (`ca.crt`, `server.crt`/`server.key`, `client.crt`/`client.key`)
- Builds ready-to-use `TlsConfig` for mutual TLS

## What it is not

- Not a production PKI
- No rotation, revocation lists, HSM, or hardware roots
- Do not present DevPki material as a security guarantee

## Usage sketch

```rust
use ikrl_transport::{DevPki, SecureListener, serve paths...};

let paths = DevPki::generate()?.materialize(std::path::Path::new("./dev-pki"))?;
let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config()).await?;
// clients: SecureChannel::connect(addr, &paths.client_mtls_config()).await?
```

`intentkernel_server::serve_mtls` accepts a `SecureListener` and speaks the same
RPC framing as the plain TCP server.
