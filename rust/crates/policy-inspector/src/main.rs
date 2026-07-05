use intentkernel_sys::syscall_types_impl::IkSyscall;
use intentkernel_sys::IkClient;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = IkClient::new_unix("/tmp/intentos.sock");
    let token = Uuid::parse_str("11111111-2222-3333-4444-555555555555")?;
    let syscall = IkSyscall::IkRead {
        handle: Uuid::new_v4(),
        len: 4096,
    };
    let resp = client.policy_explain(token, syscall)?;

    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
