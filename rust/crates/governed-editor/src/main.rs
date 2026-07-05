use intentkernel_sys::syscall_types_impl::OpenMode;
use intentkernel_sys::IkClient;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = IkClient::new_unix("/tmp/intentos.sock");
    let token_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555")?;
    let resp = client.open(token_id, "demo.txt", OpenMode::Read)?;
    println!("open response: {}", resp);
    Ok(())
}
