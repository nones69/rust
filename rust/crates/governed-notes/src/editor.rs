use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use intentkernel_sys::syscall_types_impl::OpenMode;
use intentkernel_sys::IkClient;
use uuid::Uuid;

pub struct Editor {
    client: IkClient,
    token: Uuid,
    handle: Option<Uuid>,
}

impl Editor {
    pub fn new(socket_path: &str, token: Uuid) -> Self {
        Self {
            client: IkClient::new_unix(socket_path),
            token,
            handle: None,
        }
    }

    pub fn open(&mut self, path: &str) -> Result<(), String> {
        let resp = self
            .client
            .open(self.token, path, OpenMode::ReadWrite)
            .map_err(|e| format!("open error: {e}"))?;

        let handle = resp["handle"].as_str().ok_or("missing handle")?;
        self.handle = Some(Uuid::parse_str(handle).map_err(|e| format!("{e}"))?);

        println!("Opened {}", path);
        Ok(())
    }

    pub fn read(&mut self) -> Result<(), String> {
        let handle = self.handle.ok_or("no file open")?;
        let resp = self
            .client
            .read(self.token, handle, 4096)
            .map_err(|e| format!("read error: {e}"))?;

        let data = resp["data"]
            .as_str()
            .ok_or("kernel response missing 'data' field")?;
        let bytes = BASE64.decode(data).map_err(|e| format!("{e}"))?;
        let text = String::from_utf8_lossy(&bytes);

        println!("--- file contents ---\n{text}\n---------------------");
        Ok(())
    }

    pub fn write(&mut self, text: &str) -> Result<(), String> {
        let handle = self.handle.ok_or("no file open")?;
        let resp = self
            .client
            .write(self.token, handle, text.as_bytes().to_vec())
            .map_err(|e| format!("write error: {e}"))?;

        println!("Wrote {} bytes", resp["written"].as_u64().unwrap_or(0));
        Ok(())
    }

    pub fn ai_assist(&mut self, prompt: &str) -> Result<(), String> {
        let resp = self
            .client
            .ai_infer(self.token, "stub", prompt, Some(128))
            .map_err(|e| format!("ai error: {e}"))?;

        let text = resp["text"]
            .as_str()
            .ok_or("kernel response missing 'text' field")?;
        println!("AI Suggestion:\n{text}");
        Ok(())
    }
}
