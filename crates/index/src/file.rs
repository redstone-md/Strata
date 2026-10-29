//! On-disk form of a [`DiskIndex`] (`*.sidx` in the case cache).
//!
//! ```text
//! header   "STRATAIX" | u32 version | u32 block_size | u64 disk_len | u64 scanned_to
//!          | u32 section_count | u32 crc32(header bytes before it)
//! section  u32 kind | u32 crc32(payload) | u64 payload_len | payload
//!   1 BLOCKS      u16 LE per block (see `record`)
//!   2 SIGNATURES  u32 type_count, (u8 len, key)*, u32 hit_count,
//!                 (u64 offset | u64 declared_len (MAX = none) | f32 confidence | u16 type
//!                  | u16 match_len | u8 flags (bit0 validated, bit1 R-Studio) | 3 reserved)*
//!   3 BOOTS       u32 count, (u64 found_at | u64 volume_start | u64 declared_len | u8 fs
//!                  | u8 source | 6 reserved)*
//!   4 PROVENANCE  JSON
//! ```
//! All integers little-endian. Unknown sections are skipped. A damaged block map makes the
//! file unusable (the scan rebuilds it); a damaged side table is dropped and reported.

use crate::index::{DiskIndex, Provenance};
use crate::record::BlockRecord;
use crate::side::{BootRecord, EntrySource, SignatureHit};
use std::io::Write;
use std::path::Path;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};
use strata_kernel::{Damage, Error, Result};

const MAGIC: &[u8; 8] = b"STRATAIX";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 8 + 4 + 4 + 8 + 8 + 4 + 4;
const BLOCKS: u32 = 1;
const SIGNATURES: u32 = 2;
const BOOTS: u32 = 3;
const PROVENANCE: u32 = 4;
const SIG_RECORD: usize = 32;
const BOOT_RECORD: usize = 32;
const NO_LEN: u64 = u64::MAX;

/// Reads and writes index files.
pub struct IndexFile;

impl IndexFile {
    pub fn encode(index: &DiskIndex) -> Vec<u8> {
        let sections = [
            (BLOCKS, index.records().iter().flat_map(|r| r.bits().to_le_bytes()).collect::<Vec<u8>>()),
            (SIGNATURES, encode_signatures(index.signatures())),
            (BOOTS, encode_boots(index.boot_records())),
            (PROVENANCE, serde_json::to_vec(index.provenance()).unwrap_or_default()),
        ];
        let mut out = Vec::with_capacity(HEADER_LEN + sections.iter().map(|s| s.1.len() + 16).sum::<usize>());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&index.block_size().to_le_bytes());
        out.extend_from_slice(&index.disk_len().to_le_bytes());
        out.extend_from_slice(&index.scanned_to().to_le_bytes());
        out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        for (kind, payload) in sections {
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
            out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            out.extend_from_slice(&payload);
        }
        out
    }

    /// Decode a file image. `Err` when the header or block map is unusable.
    pub fn decode(data: &[u8]) -> Result<(DiskIndex, Vec<Damage>)> {
        let header = data.get(..HEADER_LEN).ok_or_else(|| Error::format("disk index: truncated header"))?;
        if &header[..8] != MAGIC || u32_le(header, HEADER_LEN - 4) != Some(crc32fast::hash(&header[..HEADER_LEN - 4])) {
            return Err(Error::format("disk index: bad header"));
        }
        let field = |off| u64_le(header, off).unwrap_or(0);
        if u32_le(header, 8) != Some(VERSION) {
            return Err(Error::format("disk index: unsupported version"));
        }
        let block_size = u32_le(header, 12).unwrap_or(0);
        let (disk_len, scanned_to) = (field(16), field(24));
        let count = u32_le(header, 32).unwrap_or(0);
        let mut damage = Vec::new();
        let (mut records, mut signatures, mut boots, mut provenance) = (None, Vec::new(), Vec::new(), Provenance::default());
        let mut pos = HEADER_LEN;
        for _ in 0..count {
            let Some((kind, crc, payload)) = section(data, pos) else {
                damage.push(Damage::truncated(format!("disk index: section at {pos:#x} cut short")));
                break;
            };
            pos += 16 + payload.len();
            if crc32fast::hash(payload) != crc {
                damage.push(Damage::new(strata_kernel::DamageKind::Corrupt, None, format!("disk index: section {kind} checksum mismatch")));
                continue;
            }
            match kind {
                BLOCKS => records = Some(payload.as_chunks::<2>().0.iter().map(|c| BlockRecord::from_bits(u16::from_le_bytes(*c))).collect()),
                SIGNATURES => signatures = decode_signatures(payload, &mut damage),
                BOOTS => boots = decode_boots(payload),
                PROVENANCE => provenance = serde_json::from_slice(payload).unwrap_or_default(),
                _ => {}
            }
        }
        let records = records.ok_or_else(|| Error::format("disk index: block map missing or damaged"))?;
        let index = DiskIndex::from_parts(disk_len, block_size, records, scanned_to, signatures, boots, provenance)?;
        Ok((index, damage))
    }

    /// Write atomically (temporary file + rename) so a crash never leaves half a file.
    pub fn save(index: &DiskIndex, path: &Path) -> Result<()> {
        let tmp = path.with_extension("sidx.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&Self::encode(index))?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// `Ok(None)` when no file exists.
    pub fn load(path: &Path) -> Result<Option<(DiskIndex, Vec<Damage>)>> {
        match std::fs::read(path) {
            Ok(data) => Self::decode(&data).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn section(data: &[u8], pos: usize) -> Option<(u32, u32, &[u8])> {
    let kind = u32_le(data, pos)?;
    let crc = u32_le(data, pos + 4)?;
    let len = usize::try_from(u64_le(data, pos + 8)?).ok()?;
    let start = pos.checked_add(16)?;
    Some((kind, crc, data.get(start..start.checked_add(len)?)?))
}

fn encode_signatures(hits: &[SignatureHit]) -> Vec<u8> {
    let mut types: Vec<&str> = hits.iter().map(|h| h.type_key.as_str()).collect();
    types.sort_unstable();
    types.dedup();
    let mut out = (types.len() as u32).to_le_bytes().to_vec();
    for t in &types {
        let key = &t.as_bytes()[..t.len().min(255)];
        out.push(key.len() as u8);
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&(hits.len() as u32).to_le_bytes());
    for h in hits {
        let ty = types.binary_search(&h.type_key.as_str()).unwrap_or(0) as u16;
        out.extend_from_slice(&h.offset.to_le_bytes());
        out.extend_from_slice(&h.declared_len.unwrap_or(NO_LEN).to_le_bytes());
        out.extend_from_slice(&h.confidence.to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&h.match_len.to_le_bytes());
        out.push(u8::from(h.validated) | h.source.to_bits() << 1);
        out.extend_from_slice(&[0; 7]);
    }
    out
}

fn decode_signatures(p: &[u8], damage: &mut Vec<Damage>) -> Vec<SignatureHit> {
    let mut pos = 4;
    let mut types = Vec::new();
    for _ in 0..u32_le(p, 0).unwrap_or(0) {
        let Some(len) = u8_at(p, pos) else { break };
        let Some(key) = p.get(pos + 1..pos + 1 + usize::from(len)) else { break };
        types.push(String::from_utf8_lossy(key).into_owned());
        pos += 1 + usize::from(len);
    }
    let count = u32_le(p, pos).unwrap_or(0) as usize;
    let records = p.get(pos + 4..).unwrap_or_default();
    if records.len() / SIG_RECORD < count {
        damage.push(Damage::truncated("disk index: signature table shorter than its count"));
    }
    records
        .as_chunks::<SIG_RECORD>()
        .0
        .iter()
        .take(count)
        .filter_map(|r| {
            let declared = u64_le(r, 8)?;
            let flags = u8_at(r, 24)?;
            Some(SignatureHit {
                offset: u64_le(r, 0)?,
                declared_len: (declared != NO_LEN).then_some(declared),
                confidence: f32::from_bits(u32_le(r, 16)?),
                type_key: types.get(usize::from(u16_le(r, 20)?))?.clone(),
                match_len: u16_le(r, 22)?,
                validated: flags & 1 != 0,
                source: EntrySource::from_bits(flags >> 1),
            })
        })
        .collect()
}

fn encode_boots(records: &[BootRecord]) -> Vec<u8> {
    let mut out = (records.len() as u32).to_le_bytes().to_vec();
    for r in records {
        out.extend_from_slice(&r.found_at.to_le_bytes());
        out.extend_from_slice(&r.volume_start.to_le_bytes());
        out.extend_from_slice(&r.declared_len.to_le_bytes());
        out.push(BootRecord::fs_to_bits(r.fs));
        out.push(r.source.to_bits());
        out.extend_from_slice(&[0; 6]);
    }
    out
}

fn decode_boots(p: &[u8]) -> Vec<BootRecord> {
    let count = u32_le(p, 0).unwrap_or(0) as usize;
    p.get(4..)
        .unwrap_or_default()
        .as_chunks::<BOOT_RECORD>()
        .0
        .iter()
        .take(count)
        .filter_map(|r| {
            Some(BootRecord {
                found_at: u64_le(r, 0)?,
                volume_start: u64_le(r, 8)?,
                declared_len: u64_le(r, 16)?,
                fs: BootRecord::fs_from_bits(u8_at(r, 24)?),
                source: EntrySource::from_bits(u8_at(r, 25)?),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{BlockClass, Ownership, TextKind};
    use strata_kernel::ByteRange;
    use strata_volume::FsKind;

    fn sample() -> DiskIndex {
        let mut idx = DiskIndex::new(10 * 65_536 + 7, 65_536);
        for (i, r) in idx.records_mut().iter_mut().enumerate() {
            *r = BlockRecord::content(BlockClass::ALL[i % 7], TextKind::Utf16, i as f32 * 0.7);
        }
        idx.apply_ownership(&[(ByteRange::new(65_536, 3 * 65_536), Ownership::DeletedFile)]);
        idx.add_signatures([SignatureHit {
            offset: 70_000,
            match_len: 8,
            type_key: "png".into(),
            declared_len: None,
            confidence: 0.85,
            validated: true,
            source: EntrySource::Scan,
        }]);
        idx.add_signatures([SignatureHit {
            offset: 5,
            match_len: 0,
            type_key: "rstudio:XYZ".into(),
            declared_len: Some(1234),
            confidence: 0.5,
            validated: false,
            source: EntrySource::RStudio,
        }]);
        idx.add_boot_records([BootRecord { found_at: 512, volume_start: 0, declared_len: 99, fs: FsKind::Ext4, source: EntrySource::RStudio }]);
        idx.set_scanned_to(3 * 65_536);
        idx.provenance_mut().seeded_from.push("R-Studio scan: disk.scn".into());
        idx
    }

    #[test]
    fn round_trips_bit_exact() {
        let idx = sample();
        let bytes = IndexFile::encode(&idx);
        let (back, damage) = IndexFile::decode(&bytes).unwrap();
        assert!(damage.is_empty());
        assert_eq!(back, idx);
        assert_eq!(bytes.len(), HEADER_LEN + 4 * 16 + 11 * 2 + (4 + 1 + 3 + 1 + 11 + 4 + 2 * SIG_RECORD) + (4 + BOOT_RECORD) + {
            serde_json::to_vec(idx.provenance()).unwrap().len()
        });
    }

    #[test]
    fn detects_corruption() {
        let bytes = IndexFile::encode(&sample());
        let mut header = bytes.clone();
        header[20] ^= 1;
        assert!(IndexFile::decode(&header).is_err(), "header checksum");
        let mut blocks = bytes.clone();
        blocks[HEADER_LEN + 16 + 3] ^= 0x40;
        assert!(IndexFile::decode(&blocks).is_err(), "block map checksum");
        // A flipped bit in the signature table drops only that table.
        let sig_payload = HEADER_LEN + 16 + 22 + 16;
        let mut sigs = bytes.clone();
        sigs[sig_payload + 10] ^= 1;
        let (idx, damage) = IndexFile::decode(&sigs).unwrap();
        assert!(idx.signatures().is_empty() && damage.len() == 1);
        assert_eq!(idx.boot_records().len(), 1);
        assert!(IndexFile::decode(&bytes[..bytes.len() - 3]).is_ok_and(|(_, d)| d.len() == 1), "truncated tail");
        assert!(IndexFile::decode(&bytes[..10]).is_err());
    }

    #[test]
    fn save_and_load_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index-1.sidx");
        assert!(IndexFile::load(&path).unwrap().is_none());
        IndexFile::save(&sample(), &path).unwrap();
        assert_eq!(IndexFile::load(&path).unwrap().unwrap().0, sample());
        assert!(!path.with_extension("sidx.tmp").exists());
    }
}
