use uuid::Uuid;

/// In a real system, this would call the kernel's token minting syscall.
/// For now, we use the demo token.
pub fn request_notes_token() -> Uuid {
    Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("demo token parse failed")
}
