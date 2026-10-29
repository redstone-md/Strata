//! Windows NT/XP event logs (`.evt`). Records are found by their `LfLe` signature anywhere in
//! the file, so wrapped, dirty and partially overwritten logs still yield what survives.

use crate::results::Recorder;
use crate::text::utf16_at;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_timeline::EventKind;

const SIG: &[u8; 4] = b"LfLe";
const MIN_RECORD: usize = 0x38;
const MAX_RECORD: usize = 0x10000;

/// Security-log event ids that mean a logon.
const LOGON_IDS: &[u32] = &[528, 540, 4624];
const FAILED_LOGON_IDS: &[u32] = &[529, 530, 531, 532, 533, 534, 535, 536, 537, 539, 4625];

pub(crate) struct EventLog;

impl EventLog {
    pub fn is_evt(data: &[u8]) -> bool {
        u32_le(data, 0) == Some(0x30) && data.get(4..8) == Some(SIG)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let mut pos = 4;
        while pos + 4 <= data.len() {
            let Some(rel) = data[pos..].windows(4).position(|w| w == SIG) else { break };
            let sig = pos + rel;
            pos = sig + 4;
            let start = sig - 4;
            let len = u32_le(data, start).unwrap_or(0) as usize;
            if !(MIN_RECORD..=MAX_RECORD).contains(&len) {
                continue;
            }
            let Some(r) = data.get(start..start + len) else { continue };
            Self::record(r, rec);
            pos = start + len;
        }
    }

    fn record(r: &[u8], rec: &mut Recorder) {
        let number = u32_le(r, 8).unwrap_or(0);
        let generated = u32_le(r, 12).and_then(|t| Timestamp::from_unix_secs(i64::from(t)));
        let event_id = u32_le(r, 20).unwrap_or(0) & 0xffff;
        let kind = u16_le(r, 24).unwrap_or(0);
        let num_strings = usize::from(u16_le(r, 26).unwrap_or(0));
        let string_off = u32_le(r, 36).unwrap_or(0) as usize;
        let source = utf16_at(r, 56, 512);
        let computer = utf16_at(r, 56 + 2 * source.encode_utf16().count() + 2, 512);
        let strings = Self::strings(r, string_off, num_strings);
        let event_kind = if LOGON_IDS.contains(&event_id) || FAILED_LOGON_IDS.contains(&event_id) {
            EventKind::Login
        } else {
            EventKind::SystemLog
        };
        let failed = if FAILED_LOGON_IDS.contains(&event_id) { "failed logon; " } else { "" };
        let detail = format!("{failed}record {number}; type {}; computer {computer}; {}", type_name(kind), strings.join(" | "));
        rec.dated(generated, event_kind, format!("{source} event {event_id}"), detail);
    }

    fn strings(r: &[u8], off: usize, n: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut p = off;
        for _ in 0..n.min(32) {
            if p >= r.len() {
                break;
            }
            let s = utf16_at(r, p, r.len() - p);
            p += 2 * s.encode_utf16().count() + 2;
            out.push(s);
        }
        out
    }
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "error",
        2 => "warning",
        4 => "information",
        8 => "audit success",
        16 => "audit failure",
        _ => "other",
    }
}

#[cfg(test)]
pub(crate) fn build_evt(records: &[(u32, u32, &str, &[&str])]) -> Vec<u8> {
    let mut d = vec![0u8; 0x30];
    d[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    d[4..8].copy_from_slice(SIG);
    let wide = |s: &str| -> Vec<u8> { s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };
    for (i, (time, id, source, strings)) in records.iter().enumerate() {
        let mut r = vec![0u8; 56];
        r[4..8].copy_from_slice(SIG);
        r[8..12].copy_from_slice(&(i as u32 + 1).to_le_bytes());
        r[12..16].copy_from_slice(&time.to_le_bytes());
        r[16..20].copy_from_slice(&time.to_le_bytes());
        r[20..24].copy_from_slice(&id.to_le_bytes());
        r[24..26].copy_from_slice(&8u16.to_le_bytes());
        r[26..28].copy_from_slice(&(strings.len() as u16).to_le_bytes());
        r.extend(wide(source));
        r.extend(wide("ADMIN-PC"));
        let so = r.len() as u32;
        r[36..40].copy_from_slice(&so.to_le_bytes());
        for s in *strings {
            r.extend(wide(s));
        }
        r.resize(r.len().div_ceil(4) * 4 + 4, 0);
        let len = r.len() as u32;
        r[0..4].copy_from_slice(&len.to_le_bytes());
        let tail = r.len() - 4;
        r[tail..].copy_from_slice(&len.to_le_bytes());
        d.extend_from_slice(&r);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records() {
        let data = build_evt(&[(1_305_394_569, 528, "Security", &["Admin", "ADMIN-PC"]), (1_305_394_600, 6006, "EventLog", &[])]);
        assert!(EventLog::is_evt(&data));
        let mut rec = Recorder::new("evt");
        EventLog::parse(&data, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].kind(), EventKind::Login);
        assert_eq!(out.events[0].title(), "Security event 528");
        assert!(out.events[0].detail().contains("Admin"));
        assert_eq!(out.events[1].kind(), EventKind::SystemLog);
        for cut in (0..data.len()).step_by(5) {
            EventLog::parse(&data[..cut], &mut Recorder::new("t"));
        }
    }
}
