use intentos_kernel::{Handle, Kernel, SyscallOp, SyscallRequest, SyscallResult};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VfsError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("not found: {0}")]
    NotFound(String),
}

/// Native in-memory virtual filesystem for IntentOS.
pub struct VirtualFs {
    files: HashMap<PathBuf, Vec<u8>>,
    root: PathBuf,
}

impl VirtualFs {
    pub fn new() -> Self {
        let mut fs = Self {
            files: HashMap::new(),
            root: PathBuf::from("/"),
        };
        fs.seed_demo_tree();
        fs
    }

    fn seed_demo_tree(&mut self) {
        self.write_raw("/readme.txt", b"IntentOS native VFS - capability-gated.\n");
        self.write_raw(
            "/system/version",
            concat!(env!("CARGO_PKG_VERSION"), "\n").as_bytes(),
        );
        self.write_raw("/home/user/notes.txt", b"Ground-up kernel, shell, utilities.\n");
    }

    fn write_raw(&mut self, path: &str, data: &[u8]) {
        self.files.insert(PathBuf::from(path), data.to_vec());
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let mut out = self.root.clone();
        for comp in Path::new(path).components() {
            match comp {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(p) => out.push(p),
                _ => {}
            }
        }
        out
    }

    fn authorize(
        kernel: &Kernel,
        handle: Handle,
        op: SyscallOp,
        target: &str,
        payload: Vec<u8>,
    ) -> Result<(), VfsError> {
        match kernel.syscall(
            handle,
            SyscallRequest {
                op,
                target: target.into(),
                payload,
            },
        ) {
            SyscallResult::Allowed { .. } => {}
            SyscallResult::Denied(r) => return Err(VfsError::Denied(r)),
        }
        Ok(())
    }

    pub fn list(&self, kernel: &Kernel, handle: Handle, path: &str) -> Result<Vec<String>, VfsError> {
        Self::authorize(kernel, handle, SyscallOp::List, path, vec![])?;

        let base = self.resolve(path);
        let mut names = Vec::new();
        for key in self.files.keys() {
            if key.parent().map(|p| p == base).unwrap_or(false) {
                if let Some(name) = key.file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn read(&self, kernel: &Kernel, handle: Handle, path: &str) -> Result<Vec<u8>, VfsError> {
        Self::authorize(kernel, handle, SyscallOp::Read, path, vec![])?;

        let key = self.resolve(path);
        self.files
            .get(&key)
            .cloned()
            .ok_or_else(|| VfsError::NotFound(path.into()))
    }

    pub fn write(
        &mut self,
        kernel: &Kernel,
        handle: Handle,
        path: &str,
        data: &[u8],
    ) -> Result<usize, VfsError> {
        Self::authorize(kernel, handle, SyscallOp::Write, path, data.to_vec())?;

        let key = self.resolve(path);
        self.files.insert(key, data.to_vec());
        Ok(data.len())
    }

    pub fn delete(&mut self, kernel: &Kernel, handle: Handle, path: &str) -> Result<(), VfsError> {
        Self::authorize(kernel, handle, SyscallOp::Write, path, vec![])?;
        let key = self.resolve(path);
        self.files
            .remove(&key)
            .map(|_| ())
            .ok_or_else(|| VfsError::NotFound(path.into()))
    }

    pub fn rename(
        &mut self,
        kernel: &Kernel,
        source_handle: Handle,
        dest_handle: Handle,
        from: &str,
        to: &str,
    ) -> Result<(), VfsError> {
        Self::authorize(kernel, source_handle, SyscallOp::Write, from, vec![])?;
        Self::authorize(kernel, dest_handle, SyscallOp::Write, to, vec![])?;
        let source = self.resolve(from);
        let dest = self.resolve(to);
        let data = self
            .files
            .remove(&source)
            .ok_or_else(|| VfsError::NotFound(from.into()))?;
        self.files.insert(dest, data);
        Ok(())
    }
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_kernel::{Intent, TrustAnchor, wall_ms};

    fn intent(resource: &str, action: &str) -> Intent {
        Intent {
            actor: "test".into(),
            resource: resource.into(),
            action: action.into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn write_then_read_round_trip_through_gate() {
        let kernel = Kernel::boot().unwrap();
        let mut vfs = VirtualFs::new();

        // Each capability is single-use, so mint a fresh handle per syscall.
        let write_h = kernel.intent_to_handle(intent("file", "write")).unwrap();
        let n = vfs
            .write(&kernel, write_h, "/home/user/note.txt", b"hello")
            .unwrap();
        assert_eq!(n, 5);

        let read_h = kernel.intent_to_handle(intent("file", "read")).unwrap();
        let data = vfs.read(&kernel, read_h, "/home/user/note.txt").unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn read_without_read_capability_is_denied() {
        let kernel = Kernel::boot().unwrap();
        let vfs = VirtualFs::new();

        // A `dir/list` capability must not authorize a file read.
        let list_h = kernel.intent_to_handle(intent("dir", "list")).unwrap();
        let err = vfs.read(&kernel, list_h, "/readme.txt").unwrap_err();
        assert!(matches!(err, VfsError::Denied(_)), "got {err:?}");
    }

    #[test]
    fn write_without_write_capability_is_denied() {
        let kernel = Kernel::boot().unwrap();
        let mut vfs = VirtualFs::new();

        // A `file/read` capability must not authorize a write.
        let read_h = kernel.intent_to_handle(intent("file", "read")).unwrap();
        let err = vfs
            .write(&kernel, read_h, "/home/user/note.txt", b"nope")
            .unwrap_err();
        assert!(matches!(err, VfsError::Denied(_)), "got {err:?}");
    }

    #[test]
    fn test_vfs_read_denied_without_token() {
        let kernel = Kernel::boot().unwrap();
        let vfs = VirtualFs::new();
        let invalid = Handle::from_u64(0);

        let err = vfs.read(&kernel, invalid, "/readme.txt").unwrap_err();
        assert!(matches!(err, VfsError::Denied(_)));
    }

    #[test]
    fn test_vfs_write_denied_after_token_expiry_mid_operation() {
        let kernel = Kernel::boot().unwrap();
        let mut vfs = VirtualFs::new();
        let mut intent = intent("file", "write");
        intent
            .metadata
            .insert(intentos_kernel::META_REQUESTED_TTL_MS.into(), "1".into());
        let token = kernel.mint_token(intent).unwrap();
        let handle = kernel.register_token(token).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));

        let err = vfs
            .write(&kernel, handle, "/home/user/note.txt", b"late write")
            .unwrap_err();
        assert!(matches!(err, VfsError::Denied(_)));
    }

    #[test]
    fn test_vfs_rename_requires_authorization_on_both_paths() {
        let kernel = Kernel::boot().unwrap();
        let mut vfs = VirtualFs::new();
        let write_h = kernel.intent_to_handle(intent("file", "write")).unwrap();
        vfs.write(&kernel, write_h, "/home/user/src.txt", b"rename me")
            .unwrap();

        let src_h = kernel.intent_to_handle(intent("file", "write")).unwrap();
        let wrong_h = kernel.intent_to_handle(intent("file", "read")).unwrap();
        let err = vfs
            .rename(
                &kernel,
                src_h,
                wrong_h,
                "/home/user/src.txt",
                "/home/user/dst.txt",
            )
            .unwrap_err();
        assert!(matches!(err, VfsError::Denied(_)));
    }
}