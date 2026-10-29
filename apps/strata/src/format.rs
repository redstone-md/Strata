//! Human-readable formatting shared by every view.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strata_workbench::{JobKind, JobState, JobView, ProgressUnit};

const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
const SAT_PER_BTC: f64 = 100_000_000.0;

pub fn bytes(n: u64) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value >= 100.0 { format!("{value:.0} {}", UNITS[unit]) } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub fn hex_offset(n: u64) -> String {
    format!("0x{n:X}")
}

pub fn percent(fraction: f32) -> String {
    format!("{:.0}%", (fraction * 100.0).clamp(0.0, 100.0))
}

pub fn btc(sat: u64) -> String {
    format!("{:.8} BTC", sat as f64 / SAT_PER_BTC)
}

/// `n thing` / `n things`.
pub fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Source kind as a user reads it (from the `SourceKind` debug name).
pub fn source_kind(debug: &str) -> &'static str {
    match debug {
        "RawImage" => "Disk image",
        "RStudioImage" => "R-Studio image",
        "EwfImage" => "EnCase image",
        "PhysicalDrive" => "Physical drive",
        _ => "Partial image",
    }
}

/// Filesystem plus how the volume was found, from the `FsKind` / `VolumeOrigin` debug names.
pub fn volume_name(fs: &str, origin: &str) -> String {
    let fs = match fs {
        "Ntfs" => "NTFS",
        "Fat12" => "FAT12",
        "Fat16" => "FAT16",
        "Fat32" => "FAT32",
        "Ext2" => "ext2",
        "Ext3" => "ext3",
        "Ext4" => "ext4",
        "ExFat" => "exFAT",
        _ => "Unknown filesystem",
    };
    if origin == "Recovered" { format!("{fs}, recovered") } else { fs.to_string() }
}

/// What a job does, in words.
pub fn job_name(kind: JobKind) -> &'static str {
    match kind {
        JobKind::IndexFiles => "Index files",
        JobKind::Scan => "Deep scan",
        JobKind::ClassifyFiles => "Classify files",
        JobKind::Carve => "Carve free space",
        JobKind::Archives => "Unpack archives",
        JobKind::CheckBalances => "Check balances",
        JobKind::Artifacts => "Artefacts and timeline",
    }
}

/// Job state in words: `queued`, `running 29%`, `done`, `cancelled`.
pub fn job_state(job: &JobView) -> String {
    match &job.state {
        JobState::Queued => "queued".into(),
        JobState::Running => format!("running {}", percent(job.fraction())),
        JobState::Done(_) => "done".into(),
        JobState::Failed(_) => "failed".into(),
        JobState::Cancelled => "cancelled".into(),
        JobState::Interrupted => "interrupted — will resume".into(),
    }
}

/// Job state with its summary or reason: `done — 120 hits`, `failed — disk gone`.
pub fn job_state_long(job: &JobView) -> String {
    match &job.state {
        JobState::Running if job.is_paused() => "paused".into(),
        JobState::Running if job.foreign.is_some() => "running in another window".into(),
        JobState::Running => "running".into(),
        JobState::Done(s) if !s.is_empty() => format!("done — {s}"),
        JobState::Failed(e) => format!("failed — {e}"),
        _ => job_state(job),
    }
}

/// What an item-counting job counts, plural.
pub fn items(kind: JobKind) -> &'static str {
    match kind {
        JobKind::IndexFiles | JobKind::Artifacts => "volumes",
        JobKind::ClassifyFiles => "files",
        JobKind::Archives => "archives",
        JobKind::CheckBalances => "addresses",
        JobKind::Scan | JobKind::Carve => "bytes",
    }
}

/// `per_sec` units of a job as throughput: `48.2 MB/s`, `310 files/s`.
pub fn rate(job: &JobView, per_sec: f64) -> String {
    match job.unit {
        ProgressUnit::Bytes => format!("{}/s", bytes(per_sec.max(0.0) as u64)),
        ProgressUnit::Items if per_sec >= 10.0 => format!("{per_sec:.0} {}/s", items(job.kind)),
        ProgressUnit::Items => format!("{per_sec:.1} {}/s", items(job.kind)),
    }
}

/// Throughput of a running job (command bar), when it has one.
pub fn job_rate(job: &JobView) -> Option<String> {
    (job.state == JobState::Running && job.progress.per_sec > 0.0).then(|| rate(job, job.progress.per_sec))
}

/// `45s`, `3m 12s`, `1h 04m`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m {:02}s", s / 60, s % 60),
        _ => format!("{}h {:02}m", s / 3600, s % 3600 / 60),
    }
}

/// Unix seconds as time ago: `just now`, `12s ago`, `4m 10s ago`.
pub fn ago(unix: i64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    match (now - unix).max(0) {
        0..2 => "just now".into(),
        s => format!("{} ago", duration(Duration::from_secs(s as u64))),
    }
}

/// Shorten to `max` characters by cutting the middle: `C:/Users/…/wallet.dat`.
pub fn middle(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max || max < 5 {
        return s.to_string();
    }
    let tail = (max - 1) / 2;
    let head = max - 1 - tail;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes_and_names() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(650 * 1024 * 1024 * 1024), "650 GB");
        assert_eq!(hex_offset(255), "0xFF");
        assert_eq!(btc(150_000_000), "1.50000000 BTC");
        assert_eq!(count(1, "disk", "disks"), "1 disk");
        assert_eq!(volume_name("Fat32", "Recovered"), "FAT32, recovered");
    }

    #[test]
    fn formats_durations_and_cuts_the_middle() {
        assert_eq!(duration(Duration::from_secs(45)), "45s");
        assert_eq!(duration(Duration::from_secs(192)), "3m 12s");
        assert_eq!(duration(Duration::from_secs(3840)), "1h 04m");
        assert_eq!(middle("abcdefghij", 7), "abc…hij");
        assert_eq!(middle("short", 7), "short");
        assert_eq!(middle("ab/cd/ef/gh", 6).chars().count(), 6);
    }
}
