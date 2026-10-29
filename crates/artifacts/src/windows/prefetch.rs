//! Windows Prefetch (`.pf`, uncompressed formats: v17 XP/2003, v23 Vista/7, v26 Win8).

use crate::results::Recorder;
use crate::text::{filetime_at, utf16_at};
use strata_kernel::bytes::u32_le;
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_timeline::EventKind;

const MAX_FILES: usize = 1024;

pub(crate) struct Prefetch;

impl Prefetch {
    pub fn is_prefetch(data: &[u8]) -> bool {
        data.get(4..8) == Some(b"SCCA") || data.starts_with(b"MAM\x04")
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        if data.starts_with(b"MAM\x04") {
            rec.damage(Damage::new(DamageKind::Corrupt, None, "Win10 compressed prefetch (MAM) not supported"));
            return;
        }
        if data.get(4..8) != Some(b"SCCA") {
            rec.damage(Damage::corrupt(ByteRange::new(4, 4), "prefetch signature missing"));
            return;
        }
        let version = u32_le(data, 0).unwrap_or(0);
        let exe = utf16_at(data, 16, 60);
        let hash = u32_le(data, 76).unwrap_or(0);
        let (last_runs, count_off): (&[usize], usize) = match version {
            17 => (&[120], 144),
            23 => (&[128], 152),
            26 | 30 => (&[128, 136, 144, 152, 160, 168, 176, 184], 208),
            v => {
                rec.damage(Damage::new(DamageKind::Corrupt, None, format!("unknown prefetch version {v}")));
                return;
            }
        };
        let runs = u32_le(data, count_off).unwrap_or(0);
        let files = Self::file_names(data);
        let detail = format!("prefetch v{version}, hash {hash:08X}, run count {runs}; files: {}", files.join("; "));
        for (i, &off) in last_runs.iter().enumerate() {
            let label = if i == 0 { detail.clone() } else { format!("earlier run #{}; {detail}", i + 1) };
            rec.dated(filetime_at(data, off), EventKind::ProgramRun, exe.clone(), label);
        }
    }

    /// NUL-separated UTF-16 names in the filename-strings section.
    fn file_names(data: &[u8]) -> Vec<String> {
        let (Some(off), Some(len)) = (u32_le(data, 100), u32_le(data, 104)) else { return Vec::new() };
        let Some(section) = data.get(off as usize..(off as usize).saturating_add(len as usize).min(data.len())) else {
            return Vec::new();
        };
        crate::text::utf16_list(section, MAX_FILES)
    }
}

#[cfg(test)]
pub(crate) fn build_prefetch(version: u32, exe: &str, ft: u64, runs: u32, files: &[&str]) -> Vec<u8> {
    let mut d = vec![0u8; 0x100];
    d[0..4].copy_from_slice(&version.to_le_bytes());
    d[4..8].copy_from_slice(b"SCCA");
    let name: Vec<u8> = exe.encode_utf16().flat_map(u16::to_le_bytes).collect();
    d[16..16 + name.len()].copy_from_slice(&name);
    let (run_off, count_off) = if version == 17 { (120, 144) } else { (128, 152) };
    d[run_off..run_off + 8].copy_from_slice(&ft.to_le_bytes());
    d[count_off..count_off + 4].copy_from_slice(&runs.to_le_bytes());
    let strings: Vec<u8> = files.iter().flat_map(|f| f.encode_utf16().chain([0])).flat_map(u16::to_le_bytes).collect();
    d[100..104].copy_from_slice(&(0x100u32).to_le_bytes());
    d[104..108].copy_from_slice(&(strings.len() as u32).to_le_bytes());
    d.extend_from_slice(&strings);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xp_and_win7() {
        for v in [17, 23] {
            let data = build_prefetch(v, "BITCOIN.EXE", 129_498_681_690_000_000, 7, &["\\DEVICE\\HARDDISKVOLUME1\\BITCOIN\\WALLET.DAT"]);
            let mut rec = Recorder::new("prefetch");
            Prefetch::parse(&data, &mut rec);
            let out = rec.finish();
            assert_eq!(out.events.len(), 1, "v{v}");
            assert_eq!(out.events[0].title(), "BITCOIN.EXE");
            assert!(out.events[0].detail().contains("run count 7") && out.events[0].detail().contains("WALLET.DAT"));
            for cut in (0..data.len()).step_by(7) {
                Prefetch::parse(&data[..cut], &mut Recorder::new("prefetch"));
            }
        }
        let mut rec = Recorder::new("prefetch");
        Prefetch::parse(b"MAM\x04xxxx", &mut rec);
        assert_eq!(rec.finish().damage.len(), 1);
    }
}
