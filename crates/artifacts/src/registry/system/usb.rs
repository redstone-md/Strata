//! USB devices: mass storage (`Enum\USBSTOR`) and hardware wallets (`Enum\USB\VID_…`), with
//! the first-install / last-arrival / last-removal times Win7+ keeps per device.

use super::ControlSet;
use crate::host::{UsbRecord, keys};
use crate::registry::hive::Key;
use crate::results::Recorder;
use crate::text::filetime_at;
use strata_timeline::{CRYPTO_TAG, EventKind};

/// Device property set holding install / arrival / removal FILETIMEs (Win7+).
const DEVICE_TIMES: &str = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}";
/// USB vendor (and product) id prefixes of hardware wallets.
const HARDWARE_WALLETS: &[(&str, &str)] = &[
    ("VID_2C97", "Ledger"),
    ("VID_534C", "Trezor"),
    ("VID_1209&PID_53C", "Trezor"),
    ("VID_2B24", "KeepKey"),
    ("VID_03EB&PID_2402", "Digital Bitbox"),
];

pub(super) fn parse(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let h = cs.hive();
    if let Some(usbstor) = cs.at("Enum\\USBSTOR") {
        for device in h.subkeys(&usbstor) {
            for instance in h.subkeys(&device) {
                let name = h.text(&instance, "FriendlyName").unwrap_or_else(|| device.name.clone());
                let detail = format!("USBSTOR {}", device.name);
                report(cs, rec, &instance, UsbRecord { name, kind: "storage".into(), ..Default::default() }, &detail, false);
            }
        }
    }
    if let Some(usb) = cs.at("Enum\\USB") {
        for device in h.subkeys(&usb) {
            let upper = device.name.to_ascii_uppercase();
            let Some((_, brand)) = HARDWARE_WALLETS.iter().find(|(id, _)| upper.starts_with(id)) else { continue };
            for instance in h.subkeys(&device) {
                let desc = h.text(&instance, "FriendlyName").or_else(|| h.text(&instance, "DeviceDesc"));
                // `@oem12.inf,%desc%;Ledger Nano S` keeps the readable name after the last `;`.
                let desc = desc.map(|d| d.rsplit(';').next().unwrap_or(&d).to_string());
                let name = match desc {
                    Some(d) if d.to_lowercase().contains(&brand.to_lowercase()) => d,
                    Some(d) => format!("{brand} {d}"),
                    None => format!("{brand} device"),
                };
                let detail = format!("USB {}", device.name);
                report(cs, rec, &instance, UsbRecord { name, kind: "hardware wallet".into(), ..Default::default() }, &detail, true);
            }
        }
    }
}

/// Date the device from its property FILETIMEs (key last write when absent), then record it.
fn report(cs: &ControlSet<'_, '_>, rec: &mut Recorder, instance: &Key, mut device: UsbRecord, detail: &str, crypto: bool) {
    let h = cs.hive();
    let serial = instance.name.split('&').next().unwrap_or(&instance.name).to_string();
    let detail = format!("{detail}; serial {serial}");
    device.serial = Some(serial);
    let times = DEVICE_TIMES.split('\\').try_fold(instance.clone(), |k, p| h.subkey(&k, p));
    let prop = |id: &str| {
        let k = times.as_ref().and_then(|t| h.subkey(t, id)).and_then(|k| h.subkey(&k, "00000000"))?;
        h.values(&k).into_iter().find_map(|v| filetime_at(&v.data, 0))
    };
    device.first_connected = prop("0064");
    device.last_connected = prop("0066");
    device.last_removed = prop("0067");
    let mut dated = vec![(device.first_connected, "first install"), (device.last_connected, "last connected"), (device.last_removed, "last removed")];
    if dated.iter().all(|(t, _)| t.is_none()) {
        device.approximate = true;
        device.last_connected = instance.last_write;
        dated = vec![(instance.last_write, "key last write")];
    }
    for (at, what) in dated {
        if let Some(e) = rec.make(at, EventKind::UsbDevice, device.name.clone()) {
            let e = e.with_detail(format!("{detail}; {what}"));
            rec.push(if crypto { e.with_tag(CRYPTO_TAG) } else { e });
        }
    }
    rec.record(keys::USB_DEVICE, &device);
}
