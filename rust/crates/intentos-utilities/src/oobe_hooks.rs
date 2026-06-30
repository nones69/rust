//! Cross-platform OOBE bootstrap hook generators (Phase 2).

use intentos_hal::{HostOs, PlatformInfo};
use serde::{Deserialize, Serialize};

/// Install hook artifact for platform integrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobeHookManifest {
    pub platform: String,
    pub profile_id: String,
    pub hook_path: String,
    pub script: String,
}

pub fn emit_oobe_hook(platform: &PlatformInfo, profile_id: &str) -> OobeHookManifest {
    match platform.os {
        HostOs::Windows => emit_windows_hook(profile_id),
        HostOs::Linux => emit_linux_hook(profile_id),
        HostOs::Unknown => emit_generic_hook(profile_id),
    }
}

fn emit_windows_hook(profile_id: &str) -> OobeHookManifest {
    let script = format!(
        r#"# IntentOS OOBE bootstrap hook (Windows)
# Run once per user session or at login via GPO/Intune
$env:INTENTOS_STATE_DIR = "$env:USERPROFILE\.intentos"
$env:INTENTOS_SKIP_OOBE = "0"
Write-Host "IntentOS OOBE hook profile={profile_id}"
& intentos.exe -c "oobe status; kb open"
"#
    );
    OobeHookManifest {
        platform: "windows".into(),
        profile_id: profile_id.into(),
        hook_path: "%USERPROFILE%\\.intentos\\hooks\\oobe.ps1".into(),
        script,
    }
}

fn emit_linux_hook(profile_id: &str) -> OobeHookManifest {
    let script = format!(
        r#"#!/bin/sh
# IntentOS OOBE bootstrap hook (Linux)
export INTENTOS_STATE_DIR="${{HOME}}/.intentos"
export INTENTOS_SKIP_OOBE=0
echo "IntentOS OOBE hook profile={profile_id}"
intentos -c 'oobe status; kb open'
"#
    );
    OobeHookManifest {
        platform: "linux".into(),
        profile_id: profile_id.into(),
        hook_path: "~/.intentos/hooks/oobe.sh".into(),
        script,
    }
}

fn emit_generic_hook(profile_id: &str) -> OobeHookManifest {
    OobeHookManifest {
        platform: "generic".into(),
        profile_id: profile_id.into(),
        hook_path: ".intentos/hooks/oobe.txt".into(),
        script: format!("intentos oobe run # profile={profile_id}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_hal::{CpuArch, PlatformInfo};

    #[test]
    fn windows_hook_contains_profile() {
        let p = PlatformInfo {
            arch: CpuArch::X86_64,
            os: HostOs::Windows,
            hostname: "test".into(),
            logical_cpus: 4,
            backend: "win32-native",
        };
        let m = emit_oobe_hook(&p, "profile-abc");
        assert_eq!(m.platform, "windows");
        assert!(m.script.contains("profile-abc"));
    }
}