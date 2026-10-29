//! Recycle Bin: XP `RECYCLER\<SID>\INFO2` and Vista+ `$Recycle.Bin\<SID>\$I……`.

use crate::results::Recorder;
use crate::text::{ansi_at, filetime_at, utf16_at};
use strata_kernel::bytes::{u32_le, u64_le};
use strata_kernel::{Damage, DamageKind};
use strata_timeline::EventKind;

pub(crate) struct Info2;

impl Info2 {
    /// Header: version @0, record size @12; records from 20. v5 records (800 bytes) carry a
    /// Unicode path @280 that survives when the ANSI path's first byte is zeroed (restored or
    /// purged entries).
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let version = u32_le(data, 0).unwrap_or(0);
        let size = u32_le(data, 12).unwrap_or(0) as usize;
        if !matches!(size, 280 | 800) {
            rec.damage(Damage::new(DamageKind::Corrupt, None, format!("INFO2 record size {size} (version {version})")));
            return;
        }
        let mut off = 20;
        while off + 280 <= data.len() {
            let r = &data[off..(off + size).min(data.len())];
            off += size;
            let ansi = ansi_at(r, 0, 260);
            let wide = if size == 800 { utf16_at(r, 280, 520) } else { String::new() };
            let index = u32_le(r, 260).unwrap_or(0);
            let drive = u32_le(r, 264).unwrap_or(0);
            let bytes = u32_le(r, 276).unwrap_or(0);
            let purged = r.first() == Some(&0);
            let path = if !wide.is_empty() { wide } else if purged { ansi_at(r, 1, 259) } else { ansi };
            if path.is_empty() {
                continue;
            }
            let ext = path.rsplit_once('.').map(|(_, e)| format!(".{e}")).unwrap_or_default();
            let drive_letter = char::from(b'A' + (drive % 26) as u8);
            let detail = format!(
                "Recycle Bin D{}{index}{ext}; {bytes} bytes{}",
                drive_letter.to_ascii_lowercase(),
                if purged { "; entry restored or purged" } else { "" }
            );
            let Some(mut e) = rec.make(filetime_at(r, 268), EventKind::FileDeleted, path) else { continue };
            if purged {
                e.add_tag("purged");
            }
            rec.push(e.with_detail(detail));
        }
    }
}

pub(crate) struct RecycleI;

impl RecycleI {
    pub fn is_i_file(data: &[u8]) -> bool {
        matches!(u64_le(data, 0), Some(1 | 2)) && data.len() >= 28 && filetime_at(data, 16).is_some()
    }

    /// v1 (Vista/7/8): path UTF-16 @24 (520 bytes). v2 (Win10): name length @24, path @28.
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let version = u64_le(data, 0).unwrap_or(0);
        let size = u64_le(data, 8).unwrap_or(0);
        let path = match version {
            1 => utf16_at(data, 24, 520),
            2 => utf16_at(data, 28, 2 * u32_le(data, 24).unwrap_or(0) as usize),
            _ => {
                rec.damage(Damage::new(DamageKind::Corrupt, None, format!("$I version {version}")));
                return;
            }
        };
        rec.emit(filetime_at(data, 16), EventKind::FileDeleted, path, format!("Recycle Bin $I; {size} bytes"));
    }
}

#[cfg(test)]
pub(crate) fn build_info2(entries: &[(&str, u64, bool)]) -> Vec<u8> {
    let mut d = vec![0u8; 20];
    d[0..4].copy_from_slice(&5u32.to_le_bytes());
    d[12..16].copy_from_slice(&800u32.to_le_bytes());
    for (i, (path, ft, purged)) in entries.iter().enumerate() {
        let mut r = vec![0u8; 800];
        r[..path.len()].copy_from_slice(path.as_bytes());
        if *purged {
            r[0] = 0;
        }
        r[260..264].copy_from_slice(&(i as u32 + 1).to_le_bytes());
        r[264..268].copy_from_slice(&2u32.to_le_bytes());
        r[268..276].copy_from_slice(&ft.to_le_bytes());
        r[276..280].copy_from_slice(&4096u32.to_le_bytes());
        let w: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        r[280..280 + w.len()].copy_from_slice(&w);
        d.extend_from_slice(&r);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    const FT: u64 = 129_498_681_690_000_000;

    #[test]
    fn info2_and_i_files() {
        let data = build_info2(&[("C:\\Documents and Settings\\Admin\\wallet.dat", FT, false), ("C:\\old.txt", FT, true)]);
        let mut rec = Recorder::new("recycle.info2");
        Info2::parse(&data, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].title(), "C:\\Documents and Settings\\Admin\\wallet.dat");
        assert!(out.events[0].detail().contains("Dc1.dat"));
        assert!(out.events[1].has_tag("purged"));
        for cut in (0..data.len()).step_by(13) {
            Info2::parse(&data[..cut], &mut Recorder::new("t"));
        }

        let mut i = vec![0u8; 24];
        i[0..8].copy_from_slice(&2u64.to_le_bytes());
        i[8..16].copy_from_slice(&1234u64.to_le_bytes());
        i[16..24].copy_from_slice(&FT.to_le_bytes());
        let path: Vec<u8> = "C:\\Users\\A\\keys.txt\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        i.extend_from_slice(&((path.len() / 2) as u32).to_le_bytes());
        i.extend_from_slice(&path);
        assert!(RecycleI::is_i_file(&i));
        let mut rec = Recorder::new("recycle.i");
        RecycleI::parse(&i, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events[0].title(), "C:\\Users\\A\\keys.txt");
        assert_eq!(out.events[0].at().to_string(), "2011-05-14 17:36:09");
        for cut in 0..i.len() {
            RecycleI::parse(&i[..cut], &mut Recorder::new("t"));
        }
    }
}
