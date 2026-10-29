//! Timestamps from the many clocks found on disks, normalised to Unix microseconds UTC.

use serde::{Deserialize, Serialize};
use std::fmt;

/// FILETIME epoch (1601-01-01) to Unix epoch, in 100ns ticks.
const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Plausibility window for disk artefacts: 1980..2100.
    const MIN: i64 = 315_532_800_000_000;
    const MAX: i64 = 4_102_444_800_000_000;

    pub fn from_unix_micros(us: i64) -> Option<Self> {
        (Self::MIN..Self::MAX).contains(&us).then_some(Self(us))
    }

    pub fn from_unix_secs(s: i64) -> Option<Self> {
        Self::from_unix_micros(s.checked_mul(1_000_000)?)
    }

    /// Windows FILETIME (100ns since 1601). Used by NTFS, registry, LNK, IE.
    pub fn from_filetime(ft: u64) -> Option<Self> {
        let ticks = i64::try_from(ft).ok()?.checked_sub(FILETIME_UNIX_DIFF)?;
        Self::from_unix_micros(ticks / 10)
    }

    /// WebKit/Chrome time: microseconds since 1601.
    pub fn from_webkit(us: i64) -> Option<Self> {
        Self::from_unix_micros(us.checked_sub(FILETIME_UNIX_DIFF / 10)?)
    }

    /// FAT date/time words (local time, 2s resolution), treated as UTC.
    pub fn from_dos(date: u16, time: u16) -> Option<Self> {
        let year = 1980 + i64::from(date >> 9);
        let month = i64::from((date >> 5) & 0x0f);
        let day = i64::from(date & 0x1f);
        let hour = i64::from(time >> 11);
        let min = i64::from((time >> 5) & 0x3f);
        let sec = i64::from(time & 0x1f) * 2;
        Self::from_civil(year, month, day, hour, min, sec)
    }

    /// Calendar date and time of day, UTC. `None` for out-of-range fields.
    pub fn from_civil(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> Option<Self> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || !(0..24).contains(&hour) || !(0..60).contains(&min) || !(0..60).contains(&sec) {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Self::from_unix_secs(days * 86_400 + hour * 3600 + min * 60 + sec)
    }

    pub fn unix_micros(self) -> i64 {
        self.0
    }

    pub fn unix_secs(self) -> i64 {
        self.0.div_euclid(1_000_000)
    }

    /// `(year, month, day, hour, minute, second)` in UTC.
    pub fn civil(self) -> (i64, u32, u32, u32, u32, u32) {
        let secs = self.unix_secs();
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, mo, d, h, mi, s) = self.civil();
        write!(f, "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
    }
}

// Civil calendar conversions (H. Hinnant, "chrono-compatible low-level date algorithms").
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_roundtrip() {
        // 2011-05-01 12:00:00 UTC
        let ts = Timestamp::from_filetime(129_487_248_000_000_000).unwrap();
        assert_eq!(ts.to_string(), "2011-05-01 12:00:00");
        assert!(Timestamp::from_filetime(0).is_none());
    }

    #[test]
    fn dos_time() {
        let date = ((2012 - 1980) << 9) | (1 << 5) | 15;
        let time = (10 << 11) | (30 << 5) | 10;
        assert_eq!(Timestamp::from_dos(date, time).unwrap().to_string(), "2012-01-15 10:30:20");
    }
}
