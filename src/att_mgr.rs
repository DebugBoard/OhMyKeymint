use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::config::{config, DeviceProperty};

pub struct AttestationIdMgr;

static ATTESTATION_IDS: Mutex<Option<AttestationIdInfo>> = Mutex::new(None);
/// Set when the most recent snapshot was built without the telephony identifiers that the
/// device may still report later on, so callers know not to hold on to it.
static PROVISIONAL_IDS: AtomicBool = AtomicBool::new(false);

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        self.get_ids()?
            .ok_or_else(|| km_err!(CannotAttestIds, "attestation ID info not available"))
    }

    fn get_ids(&self) -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
        let mut cached = ATTESTATION_IDS
            .lock()
            .map_err(|_| km_err!(UnknownError, "attestation ID cache lock poisoned"))?;
        if let Some(ids) = cached.as_ref() {
            PROVISIONAL_IDS.store(false, Ordering::Relaxed);
            return Ok(Some(ids.clone()));
        }

        let configured = config()
            .read()
            .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?
            .device
            .clone();

        let (ids, provisional) = attestation_snapshot(configured, || {
            crate::plat::device_ids::resolve_runtime_device_ids()
        });

        PROVISIONAL_IDS.store(provisional, Ordering::Relaxed);
        if !provisional {
            *cached = Some(ids.clone());
        }
        Ok(Some(ids))
    }

    fn ids_are_provisional(&self) -> bool {
        PROVISIONAL_IDS.load(Ordering::Relaxed)
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}

fn needs_resolution(device: &DeviceProperty) -> bool {
    !device.override_telephony_properties
        && (device.imei.trim().is_empty()
            || device.imei2.trim().is_empty()
            || device.meid.trim().is_empty())
}

/// Build the attestation ID snapshot for `configured`, backfilling the telephony identifiers with
/// `resolve` when the configuration leaves them empty.
///
/// Telephony identifiers are only a part of the attestation identity: brand, device, product,
/// manufacturer, model, and serial come from the configuration and never need telephony at all.
/// So when `resolve` cannot answer yet (the telephony Binder services are not up, which is normal
/// early in boot), fall back to the configured identity instead of refusing to attest anything.
/// Refusing here fails every attestation ID request with `CannotAttestIds`, including the
/// device-properties-only requests made by `setDevicePropertiesAttestationIncluded(true)`.
///
/// The second element of the returned pair reports whether the snapshot is provisional, i.e. built
/// without a completed telephony resolution and therefore not safe to cache.
fn attestation_snapshot(
    configured: DeviceProperty,
    resolve: impl FnOnce() -> anyhow::Result<Option<DeviceProperty>>,
) -> (AttestationIdInfo, bool) {
    let (device, provisional) = if needs_resolution(&configured) {
        match resolve() {
            Ok(Some(device)) => (device, false),
            Ok(None) => {
                log::warn!(
                    "telephony identifiers are not available yet; attesting the configured device \
                     identity without them"
                );
                (configured, true)
            }
            Err(error) => {
                log::warn!(
                    "failed to resolve runtime attestation IDs: {error:#}; attesting the \
                     configured device identity without telephony identifiers"
                );
                (configured, true)
            }
        }
    } else {
        (configured, false)
    };

    (snapshot_from(device), provisional)
}

fn snapshot_from(device: DeviceProperty) -> AttestationIdInfo {
    AttestationIdInfo {
        brand: device.brand.into_bytes(),
        device: device.device.into_bytes(),
        product: device.product.into_bytes(),
        serial: device.serial.into_bytes(),
        imei: device.imei.into_bytes(),
        imei2: device.imei2.into_bytes(),
        meid: device.meid.into_bytes(),
        manufacturer: device.manufacturer.into_bytes(),
        model: device.model.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn configured_device() -> DeviceProperty {
        DeviceProperty {
            brand: "Redmi".to_string(),
            device: "zorn".to_string(),
            product: "zorn_global".to_string(),
            manufacturer: "Xiaomi".to_string(),
            model: "24069PC21G".to_string(),
            serial: "f7bade12".to_string(),
            override_telephony_properties: false,
            meid: String::new(),
            imei: String::new(),
            imei2: String::new(),
        }
    }

    #[test]
    fn deferred_telephony_still_attests_device_properties() {
        let (ids, provisional) = attestation_snapshot(configured_device(), || Ok(None));

        assert!(
            provisional,
            "snapshot without telephony IDs must not be cached"
        );
        assert_eq!(ids.brand, b"Redmi".to_vec());
        assert_eq!(ids.device, b"zorn".to_vec());
        assert_eq!(ids.product, b"zorn_global".to_vec());
        assert_eq!(ids.manufacturer, b"Xiaomi".to_vec());
        assert_eq!(ids.model, b"24069PC21G".to_vec());
        assert!(ids.imei.is_empty());
    }

    #[test]
    fn failed_telephony_resolution_still_attests_device_properties() {
        let (ids, provisional) = attestation_snapshot(configured_device(), || {
            Err(anyhow::anyhow!("telephony service is not ready"))
        });

        assert!(provisional);
        assert_eq!(ids.model, b"24069PC21G".to_vec());
        assert!(ids.meid.is_empty());
    }

    #[test]
    fn resolved_telephony_identifiers_are_cacheable() {
        let mut resolved = configured_device();
        resolved.imei = "490154203237518".to_string();

        let (ids, provisional) = attestation_snapshot(configured_device(), || Ok(Some(resolved)));

        assert!(!provisional);
        assert_eq!(ids.imei, b"490154203237518".to_vec());
    }

    #[test]
    fn pinned_configuration_skips_resolution() {
        let mut device = configured_device();
        device.override_telephony_properties = true;
        device.imei = "490154203237518".to_string();
        let called = Cell::new(false);

        let (ids, provisional) = attestation_snapshot(device, || {
            called.set(true);
            Ok(None)
        });

        assert!(!called.get(), "pinned identifiers must not hit telephony");
        assert!(!provisional);
        assert_eq!(ids.imei, b"490154203237518".to_vec());
    }
}
