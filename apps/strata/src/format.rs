//! Human-readable formatting shared by every view.

use strata_workbench::{JobKind, JobState, JobView};

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

/// Throughput, shown only for jobs that read the disk sequentially.
pub fn job_rate(job: &JobView) -> Option<String> {
    (job.kind == JobKind::Scan && job.progress.per_sec > 0.0)
        .then(|| format!("{}/s", bytes(job.progress.per_sec as u64)))
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
}
