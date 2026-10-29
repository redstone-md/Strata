//! Export the data behind a finding: a file carved from free space, or a member unpacked
//! from an archive. Written with the same writer and log as file recovery.

use super::writer::{Item, Recovered, RecoveryWriter};
use strata_case::{Case, StoredHit};
use strata_identify::Registry;
use strata_kernel::{ByteRange, Error, Result};

/// What a finding can be exported as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exportable {
    Carved { range: ByteRange, type_name: String },
    ArchiveMember { member_path: String },
}

impl Exportable {
    pub fn of(hit: &StoredHit) -> Option<Self> {
        if hit.hit.detector.starts_with("carve.") {
            let range: ByteRange = serde_json::from_value(hit.hit.details.get("range")?.clone()).ok()?;
            let type_name = hit.hit.details.pointer("/verdict/type_name").and_then(|v| v.as_str()).unwrap_or("data").to_string();
            return Some(Self::Carved { range, type_name });
        }
        let path = hit.file_path.as_deref()?;
        path.contains("!/").then(|| Self::ArchiveMember { member_path: path.to_string() })
    }

    pub fn action(&self) -> &'static str {
        match self {
            Self::Carved { .. } => "Export carved file",
            Self::ArchiveMember { .. } => "Export archive member",
        }
    }
}

fn extension(type_name: &str) -> &'static str {
    Registry::all().iter().find(|t| t.name == type_name).and_then(|t| t.extensions.first().copied()).unwrap_or("bin")
}

/// Write the finding's data under `<dest>/<disk>/$Carved` or `<dest>/<disk>/$Archives`.
pub fn export(case: &Case, hit: &StoredHit, dest: &std::path::Path) -> Result<Recovered> {
    let what = Exportable::of(hit).ok_or_else(|| Error::Other("this finding is not a carved file or an archive member".into()))?;
    let id = hit.evidence;
    let disk = case.record(id)?.info.label;
    let locations: Vec<String> = case.evidence()?.into_iter().map(|e| e.info.location).collect();
    let mut writer = RecoveryWriter::open(dest, &locations)?;
    let recovered = match what {
        Exportable::Carved { range, type_name } => {
            let source = case.source(id)?;
            let damage: Vec<String> = hit.hit.details.get("damage").and_then(|d| d.as_array()).into_iter().flatten()
                .filter_map(|d| d.get("note").and_then(|n| n.as_str()).map(str::to_string))
                .collect();
            let item = Item { source_path: hit.hit.value.clone(), state: "carved".into(), size: range.len(), intact: range.len(), damage };
            let name = format!("{type_name}@{:#x}.{}", range.start(), extension(&type_name));
            let mut read = |off: u64, buf: &mut [u8]| source.read_at(range.start() + off, buf);
            writer.write(&[disk, "$Carved".into(), name], &item, &mut read)?
        }
        Exportable::ArchiveMember { member_path } => {
            let (bytes, damage) = crate::steps::archives::extract_member(case, id, &member_path)?;
            let item = Item { source_path: member_path.clone(), state: "archive member".into(), size: bytes.len() as u64, intact: bytes.len() as u64, damage };
            let mut components = vec![disk, "$Archives".into()];
            components.extend(member_path.split("!/").flat_map(|p| p.split('/')).filter(|c| !c.is_empty()).map(str::to_string));
            let mut read = |off: u64, buf: &mut [u8]| {
                let start = (off as usize).min(bytes.len());
                let n = buf.len().min(bytes.len() - start);
                buf[..n].copy_from_slice(&bytes[start..start + n]);
                Ok(n)
            };
            writer.write(&components, &item, &mut read)?
        }
    };
    writer.finish()?;
    Ok(recovered)
}
