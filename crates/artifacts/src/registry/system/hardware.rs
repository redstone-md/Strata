//! Hardware hints the SYSTEM hive keeps: processor (ACPI enumeration), video adapters, board and
//! BIOS (`Control\SystemInformation`, Vista+) and the disk drives that were attached.

use super::ControlSet;
use crate::host::keys;
use crate::results::Recorder;
use std::collections::BTreeMap;

/// Display adapters device class.
const VIDEO: &str = "Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}";
/// Disk drive enumerators.
const DISK_BUSES: &[&str] = &["Enum\\IDE", "Enum\\SCSI"];
/// Disk drives listed per machine (old machines see few; servers with arrays see many).
const MAX_DISKS: usize = 32;

pub(super) fn parse(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    processors(cs, rec);
    video(cs, rec);
    system_model(cs, rec);
    disks(cs, rec);
}

/// `Enum\ACPI\GenuineIntel_-_x86_Family_6_Model_23\_0` with the model in `FriendlyName`; one
/// instance per core, reported once with the core count.
fn processors(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let h = cs.hive();
    let Some(acpi) = cs.at("Enum\\ACPI") else { return };
    let mut cores: BTreeMap<String, usize> = BTreeMap::new();
    for cpu in h.subkeys(&acpi).into_iter().filter(|k| k.name.contains("_-_")) {
        for core in h.subkeys(&cpu) {
            let name = h.text(&core, "FriendlyName").unwrap_or_else(|| cpu.name.replace('_', " "));
            *cores.entry(squeeze(&name)).or_default() += 1;
        }
    }
    for (name, n) in cores {
        rec.fact(keys::CPU, if n > 1 { format!("{name} × {n}") } else { name });
    }
}

fn video(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let h = cs.hive();
    let Some(class) = cs.at(VIDEO) else { return };
    for k in h.subkeys(&class).into_iter().filter(|k| k.name.bytes().all(|b| b.is_ascii_digit())) {
        if let Some(name) = h.text(&k, "DriverDesc") {
            rec.fact(keys::VIDEO, name);
        }
    }
}

fn system_model(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let path = "Control\\SystemInformation";
    let maker = cs.text(path, "SystemManufacturer");
    let model = cs.text(path, "SystemProductName");
    let bios = [cs.text(path, "BIOSVersion"), cs.text(path, "BIOSReleaseDate")].into_iter().flatten().collect::<Vec<_>>().join(", ");
    let mut text = [maker, model].into_iter().flatten().collect::<Vec<_>>().join(" ");
    if !bios.is_empty() {
        text = format!("{text} (BIOS {bios})").trim().to_string();
    }
    rec.fact(keys::SYSTEM_MODEL, text);
}

/// `Enum\IDE\DiskST3500418AS_____________CC38\<instance>`: model from `FriendlyName`, else
/// from the device key name.
fn disks(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let h = cs.hive();
    let mut seen = Vec::new();
    for bus in DISK_BUSES {
        let Some(bus) = cs.at(bus) else { continue };
        for device in h.subkeys(&bus).into_iter().filter(|k| k.name.to_ascii_lowercase().starts_with("disk")) {
            let friendly = h.subkeys(&device).iter().find_map(|i| h.text(i, "FriendlyName"));
            let name = friendly.unwrap_or_else(|| model_of(&device.name));
            if !name.is_empty() && !seen.contains(&name) && seen.len() < MAX_DISKS {
                seen.push(name.clone());
                rec.fact(keys::DISK_DRIVE, name);
            }
        }
    }
}

/// `DiskST3500418AS_____________CC38` / `Disk&Ven_WDC&Prod_WD5000AAKS` → readable model.
fn model_of(device: &str) -> String {
    let rest = device.get(4..).unwrap_or_default();
    let parts: Vec<&str> = rest.split('&').filter(|p| !p.is_empty()).collect();
    let text = if parts.len() > 1 {
        parts.iter().filter_map(|p| p.split_once('_').map(|(_, v)| v)).filter(|v| !v.is_empty()).take(2).collect::<Vec<_>>().join(" ")
    } else {
        rest.split("__").next().unwrap_or(rest).to_string()
    };
    squeeze(&text.replace('_', " "))
}

/// Collapse runs of spaces (CPU names are padded).
fn squeeze(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::model_of;

    #[test]
    fn disk_models_from_key_names() {
        assert_eq!(model_of("DiskST3500418AS_____________________________CC38____"), "ST3500418AS");
        assert_eq!(model_of("Disk&Ven_WDC&Prod_WD5000AAKS-00V1A0&Rev_05.0"), "WDC WD5000AAKS-00V1A0");
    }
}
