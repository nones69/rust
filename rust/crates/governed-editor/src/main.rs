use intentkernel_sys::{KernelClient, SyscallOp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Endpoint can be overridden at runtime via KERNEL_ADDR environment variable.
    // Defaults to the loopback TCP address used by the kernel IPC server.
    let addr = std::env::var("KERNEL_ADDR")
        .unwrap_or_else(|_| "tcp://127.0.0.1:9500".to_string());

    let mut client = KernelClient::connect_local(&addr).await?;

    // Mint a token then immediately exercise a read syscall.
    let jti = client.mint_token("governed-editor", "file", "read").await?;
    println!("token issued jti={jti}");

    // For the demo, use a synthetic handle value (0). In a real deployment
    // the token would be registered via capd→eventscope to obtain a handle.
    let result = client.syscall(0, SyscallOp::Read, "demo.txt", vec![]).await;
    match result {
        Ok(v) => println!("syscall result: {v}"),
        Err(e) => println!("syscall denied (expected in demo): {e}"),
    }

    Ok(())
}
