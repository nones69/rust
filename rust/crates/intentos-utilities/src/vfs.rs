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

    pub fn list(&self, kernel: &Kernel, handle: Handle, path: &str) -> Result<Vec<String>, VfsError> {
        match kernel.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::List,
                target: path.into(),
                payload: vec![],
            },
        ) {
            SyscallResult::Allowed { .. } => {}
            SyscallResult::Denied(r) => return Err(VfsError::Denied(r)),
        }

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
        match kernel.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Read,
                target: path.into(),
                payload: vec![],
            },
        ) {
            SyscallResult::Allowed { .. } => {}
            SyscallResult::Denied(r) => return Err(VfsError::Denied(r)),
        }

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
        match kernel.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Write,
                target: path.into(),
                payload: data.to_vec(),
            },
        ) {
            SyscallResult::Allowed { .. } => {}
            SyscallResult::Denied(r) => return Err(VfsError::Denied(r)),
        }

        let key = self.resolve(path);
        self.files.insert(key, data.to_vec());
        Ok(data.len())
    }
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new()
    }
}