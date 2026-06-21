//! IoT/embedded sector plugin scaffold — OTA/secure-boot-shaped intent mapping (Phase 2).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// Device fleet / firmware-oriented command → capability intent mapper (rule-based pilot).
pub struct IotMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMapping {
    pub domain: String,
    pub action: String,
    pub original: String,
}

impl IotMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "OTA.publish",
        "OTA.rollback",
        "OTA.status",
        "Boot.verify",
        "Device.provision",
        "Device.telemetry",
        "Device.identity.rotate",
        "MQTT.publish",
        "CoAP.get",
        "Edge.infer",
        "POST /firmware",
        "GET /device/status",
    ];

    pub fn map(cmd: &str) -> Option<DeviceMapping> {
        let trimmed = cmd.trim();
        let lower = trimmed.to_lowercase();

        let (domain, action) = match lower.as_str() {
            "ota.publish" | "post /firmware" => ("ota", "publish"),
            "ota.rollback" => ("ota", "rollback"),
            "ota.status" | "get /device/status" => ("ota", "status"),
            "boot.verify" => ("boot", "verify"),
            "device.provision" => ("device", "provision"),
            "device.telemetry" => ("device", "telemetry"),
            "device.identity.rotate" => ("device", "rotate"),
            "mqtt.publish" => ("mqtt", "publish"),
            "coap.get" => ("coap", "read"),
            "edge.infer" => ("edge", "infer"),
            _ => return None,
        };

        Some(DeviceMapping {
            domain: domain.into(),
            action: action.into(),
            original: trimmed.into(),
        })
    }

    pub fn to_intent(mapped: &DeviceMapping, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.domain.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "iot".into()),
                ("device_op".into(), mapped.original.clone()),
                ("iec62443_mode".into(), "stub".into()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "iot `{}` -> {}/{}",
                mapped.original, mapped.domain, mapped.action
            ),
        );
        Some(Self::to_intent(&mapped, actor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ota_publish() {
        let mapped = IotMapper::map("OTA.publish").expect("map");
        assert_eq!(mapped.domain, "ota");
        assert_eq!(mapped.action, "publish");
    }
}