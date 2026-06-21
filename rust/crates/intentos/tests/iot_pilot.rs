//! Phase 2 IoT/embedded sector scaffold tests.

use intentos_utilities::{IotAssessor, IotMapper, OsRuntime};

#[test]
fn iot_mapper_ota_publish() {
    let mapped = IotMapper::map("OTA.publish").expect("map");
    assert_eq!(mapped.domain, "ota");
    assert_eq!(mapped.action, "publish");
}

#[test]
fn iot_assessor_not_pilot_ready() {
    let rt = OsRuntime::boot().expect("boot");
    let report = IotAssessor::assess(&rt.platform);
    assert_eq!(report.sector, "iot");
    assert!(!report.pilot_ready);
    assert!(report.blockers.iter().any(|b| b.contains("OTA")));
    assert!(!report.hal_arch.is_empty());
}

#[test]
fn iot_map_and_audit() {
    let rt = OsRuntime::boot().expect("boot");
    let intent = IotMapper::map_and_audit("Boot.verify", "fleet-admin", &rt.audit).expect("map");
    assert_eq!(intent.resource, "boot");
    assert_eq!(
        intent.metadata.get("sector").map(String::as_str),
        Some("iot")
    );
}