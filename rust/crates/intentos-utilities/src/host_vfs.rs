use crate::syscall_envelope::OpenMode;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::Mutex;
use uuid::Uuid;

lazy_static! {
    static ref HANDLE_TABLE: Mutex<HashMap<Uuid, std::fs::File>> = Mutex::new(HashMap::new());
}

fn governed_root_for_token(_token_id: &Uuid) -> String {
    // For demo, use a fixed safe root directory.
    "/tmp/intentos_root".to_string()
}

pub fn vfs_open(token_id: &Uuid, path: &str, mode: OpenMode) -> Result<Uuid, String> {
    let root = governed_root_for_token(token_id);
    let full = format!(
        "{}/{}",
        root.trim_end_matches('/'),
        path.trim_start_matches('/')
    );

    // Prevent path traversal by canonicalizing and ensuring prefix matches root
    let canonical = std::path::Path::new(&full)
        .canonicalize()
        .map_err(|e| format!("canonicalize error: {}", e))?;
    let root_canon = std::path::Path::new(&root)
        .canonicalize()
        .map_err(|e| format!("root canonicalize error: {}", e))?;
    if !canonical.starts_with(&root_canon) {
        return Err("path traversal detected".to_string());
    }

    let mut opts = OpenOptions::new();
    match mode {
        OpenMode::Read => {
            opts.read(true);
        }
        OpenMode::Write => {
            opts.write(true);
        }
        OpenMode::ReadWrite => {
            opts.read(true).write(true);
        }
        OpenMode::Create => {
            opts.create(true).write(true);
        }
    }

    let file = opts
        .open(&canonical)
        .map_err(|e| format!("open error: {}", e))?;
    let handle = Uuid::new_v4();
    HANDLE_TABLE.lock().unwrap().insert(handle, file);
    Ok(handle)
}

pub fn vfs_read(_token_id: &Uuid, handle: Uuid, len: u64) -> Result<Vec<u8>, String> {
    let mut table = HANDLE_TABLE.lock().unwrap();
    let file = table
        .get_mut(&handle)
        .ok_or_else(|| "invalid handle".to_string())?;
    let mut buf = vec![0u8; len as usize];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("read error: {}", e))?;
    buf.truncate(n);
    Ok(buf)
}

pub fn vfs_write(_token_id: &Uuid, handle: Uuid, data: &[u8]) -> Result<(), String> {
    let mut table = HANDLE_TABLE.lock().unwrap();
    let file = table
        .get_mut(&handle)
        .ok_or_else(|| "invalid handle".to_string())?;
    file.write_all(data)
        .map_err(|e| format!("write error: {}", e))?;
    Ok(())
}
