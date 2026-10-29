//! Windows shell links (`.lnk`, MS-SHLLINK): target times, target path, volume serial/label,
//! tracker machine id.

use crate::results::Recorder;
use crate::text::{ansi_at, filetime_at, utf16_at};
use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, Timestamp};
use strata_timeline::EventKind;

const HEADER_SIZE: u32 = 0x4C;
const CLSID: [u8; 16] = [0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
const HAS_ID_LIST: u32 = 0x01;
const HAS_LINK_INFO: u32 = 0x02;
const IS_UNICODE: u32 = 0x80;
const TRACKER_SIG: u32 = 0xA000_0003;

/// Decoded shell link.
#[derive(Debug, Default, Clone)]
pub(crate) struct Lnk {
    pub created: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub size: u32,
    pub target: String,
    pub arguments: String,
    pub volume_serial: Option<u32>,
    pub volume_label: String,
    pub machine_id: String,
}

impl Lnk {
    pub fn is_lnk(data: &[u8]) -> bool {
        u32_le(data, 0) == Some(HEADER_SIZE) && data.get(4..20) == Some(&CLSID)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) -> Option<Lnk> {
        if !Self::is_lnk(data) {
            rec.damage(Damage::corrupt(ByteRange::new(0, 20), "not a shell link header"));
            return None;
        }
        let flags = u32_le(data, 20)?;
        let mut lnk = Lnk {
            created: filetime_at(data, 28),
            accessed: filetime_at(data, 36),
            modified: filetime_at(data, 44),
            size: u32_le(data, 52).unwrap_or(0),
            ..Default::default()
        };
        let mut off = HEADER_SIZE as usize;
        let mut id_list_path = String::new();
        if flags & HAS_ID_LIST != 0 {
            let len = usize::from(u16_le(data, off).unwrap_or(0));
            id_list_path = crate::pidl::decode(data.get(off + 2..off + 2 + len).unwrap_or(&[]));
            off += 2 + len;
        }
        if flags & HAS_LINK_INFO != 0 {
            let size = u32_le(data, off).unwrap_or(0) as usize;
            match data.get(off..off + size) {
                Some(info) => lnk.link_info(info),
                None => rec.damage(Damage::truncated("LNK LinkInfo runs past end of file")),
            }
            off += size;
        }
        let strings = Self::string_data(data, &mut off, flags);
        lnk.arguments = strings.get(3).cloned().unwrap_or_default();
        if lnk.target.is_empty() {
            let relative = strings.get(1).cloned().unwrap_or_default();
            lnk.target = if id_list_path.is_empty() { relative } else { id_list_path };
        }
        lnk.extra_data(data, off);
        lnk.record(rec);
        Some(lnk)
    }

    fn link_info(&mut self, info: &[u8]) {
        let header = u32_le(info, 4).unwrap_or(0);
        let li_flags = u32_le(info, 8).unwrap_or(0);
        let field = |o: usize| u32_le(info, o).map(|v| v as usize).filter(|v| *v > 0);
        if li_flags & 1 != 0 {
            if let Some(vol) = field(12) {
                self.volume_serial = u32_le(info, vol + 8);
                let label_off = u32_le(info, vol + 12).unwrap_or(0) as usize;
                self.volume_label = if label_off == 0x14 {
                    utf16_at(info, vol + u32_le(info, vol + 16).unwrap_or(0) as usize, 64)
                } else {
                    ansi_at(info, vol + label_off, 64)
                };
            }
            let unicode_base = (header >= 0x24).then(|| field(28)).flatten();
            self.target = match unicode_base {
                Some(o) => utf16_at(info, o, 1040),
                None => field(16).map(|o| ansi_at(info, o, 520)).unwrap_or_default(),
            };
        }
        if li_flags & 2 != 0
            && let Some(cnrl) = field(20)
        {
            let net = ansi_at(info, cnrl + u32_le(info, cnrl + 8).unwrap_or(0) as usize, 260);
            if self.target.is_empty() {
                self.target = net;
            }
        }
        let suffix = field(24).map(|o| ansi_at(info, o, 260)).unwrap_or_default();
        if !suffix.is_empty() {
            let sep = if self.target.ends_with('\\') || self.target.is_empty() { "" } else { "\\" };
            self.target = format!("{}{sep}{suffix}", self.target);
        }
    }

    /// NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION (present per flag bits 2..6).
    fn string_data(data: &[u8], off: &mut usize, flags: u32) -> Vec<String> {
        let unicode = flags & IS_UNICODE != 0;
        (0..5)
            .map(|i| {
                if flags & (0x04 << i) == 0 {
                    return String::new();
                }
                let chars = usize::from(u16_le(data, *off).unwrap_or(0));
                let bytes = if unicode { chars * 2 } else { chars };
                let s = data.get(*off + 2..*off + 2 + bytes).map(|b| if unicode { utf16_at(b, 0, bytes) } else { ansi_at(b, 0, bytes) });
                *off += 2 + bytes;
                s.unwrap_or_default()
            })
            .collect()
    }

    fn extra_data(&mut self, data: &[u8], mut off: usize) {
        for _ in 0..64 {
            let size = u32_le(data, off).unwrap_or(0) as usize;
            if size < 8 {
                break;
            }
            if u32_le(data, off + 4) == Some(TRACKER_SIG) {
                self.machine_id = ansi_at(data, off + 16, 16);
            }
            off += size;
        }
    }

    fn record(&self, rec: &mut Recorder) {
        let target = if self.target.is_empty() { "(unknown target)".to_string() } else { self.target.clone() };
        let mut detail = format!("LNK target times; size {}", self.size);
        if let Some(s) = self.volume_serial {
            detail.push_str(&format!("; volume {:04X}-{:04X} '{}'", s >> 16, s & 0xffff, self.volume_label));
            rec.fact("volume_serial", format!("{:04X}-{:04X} {}", s >> 16, s & 0xffff, self.volume_label));
        }
        if !self.machine_id.is_empty() {
            detail.push_str(&format!("; machine {}", self.machine_id));
            rec.fact("machine_id", self.machine_id.clone());
        }
        if !self.arguments.is_empty() {
            detail.push_str(&format!("; args {}", self.arguments));
        }
        rec.dated(self.created, EventKind::FileCreated, target.clone(), detail.clone());
        rec.dated(self.modified, EventKind::FileModified, target.clone(), detail.clone());
        rec.dated(self.accessed, EventKind::FileAccessed, target, detail);
    }
}

#[cfg(test)]
pub(crate) fn build_lnk(target: &str, ft: u64, serial: u32, label: &str, machine: &str) -> Vec<u8> {
    let mut d = vec![0u8; 0x4C];
    d[0..4].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    d[4..20].copy_from_slice(&CLSID);
    d[20..24].copy_from_slice(&(HAS_LINK_INFO | IS_UNICODE).to_le_bytes());
    for o in [28, 36, 44] {
        d[o..o + 8].copy_from_slice(&ft.to_le_bytes());
    }
    // LinkInfo: header 0x1C, VolumeID at 0x1C, LocalBasePath after it.
    let mut vol = vec![0u8; 0x10];
    vol[4..8].copy_from_slice(&3u32.to_le_bytes());
    vol[8..12].copy_from_slice(&serial.to_le_bytes());
    vol[12..16].copy_from_slice(&0x10u32.to_le_bytes());
    vol.extend_from_slice(label.as_bytes());
    vol.push(0);
    let vol_len = vol.len() as u32;
    vol[0..4].copy_from_slice(&vol_len.to_le_bytes());
    let base_off = 0x1C + vol.len();
    let mut info = vec![0u8; 0x1C];
    info[4..8].copy_from_slice(&0x1Cu32.to_le_bytes());
    info[8..12].copy_from_slice(&1u32.to_le_bytes());
    info[12..16].copy_from_slice(&0x1Cu32.to_le_bytes());
    info[16..20].copy_from_slice(&(base_off as u32).to_le_bytes());
    info.extend_from_slice(&vol);
    info.extend_from_slice(target.as_bytes());
    info.push(0);
    let suffix_off = info.len() as u32;
    info.push(0);
    info[24..28].copy_from_slice(&suffix_off.to_le_bytes());
    let info_len = info.len() as u32;
    info[0..4].copy_from_slice(&info_len.to_le_bytes());
    d.extend_from_slice(&info);
    let mut tracker = vec![0u8; 0x60];
    tracker[0..4].copy_from_slice(&0x60u32.to_le_bytes());
    tracker[4..8].copy_from_slice(&TRACKER_SIG.to_le_bytes());
    tracker[16..16 + machine.len()].copy_from_slice(machine.as_bytes());
    d.extend_from_slice(&tracker);
    d.extend_from_slice(&[0; 4]);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lnk() {
        let data = build_lnk("D:\\Bitcoin\\wallet.dat", 129_498_681_690_000_000, 0x1234_ABCD, "DATA", "admin-pc");
        let mut rec = Recorder::new("lnk");
        let lnk = Lnk::parse(&data, &mut rec).unwrap();
        assert_eq!(lnk.target, "D:\\Bitcoin\\wallet.dat");
        assert_eq!(lnk.volume_label, "DATA");
        assert_eq!(lnk.machine_id, "admin-pc");
        let out = rec.finish();
        assert_eq!(out.events.len(), 3);
        assert!(out.events[0].detail().contains("1234-ABCD"));
        assert!(out.facts.iter().any(|f| f.key == "machine_id"));
    }

    #[test]
    fn truncated_lnk() {
        let data = build_lnk("C:\\x.txt", 129_498_681_690_000_000, 1, "", "m");
        for cut in 0..data.len() {
            let _ = Lnk::parse(&data[..cut], &mut Recorder::new("lnk"));
        }
    }
}
