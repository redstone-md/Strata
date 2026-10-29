//! External 7-Zip (`7z.exe`) as a fallback reader, and temp copies of archive bytes for
//! decoders that only take paths. Only copies are written; evidence is never touched.

use crate::codec::read_limited;
use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use strata_kernel::{Damage, DamageKind, Error, Result, Timestamp};

/// A copy of archive bytes in the scratch folder, removed on drop.
pub(crate) struct TempCopy {
    path: PathBuf,
}

impl TempCopy {
    pub fn write(dir: &Path, bytes: &[u8], ext: &str) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(dir)?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("strata-{}-{n}.{ext}", std::process::id()));
        let mut f = std::fs::File::create(&path)?;
        f.write_all(bytes)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The 7-Zip command-line program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZipTool {
    exe: PathBuf,
}

impl SevenZipTool {
    pub fn new(exe: impl Into<PathBuf>) -> Self {
        Self { exe: exe.into() }
    }

    /// 7-Zip from its standard install folders, if present.
    pub fn detect() -> Option<Self> {
        ["C:\\Program Files\\7-Zip\\7z.exe", "C:\\Program Files (x86)\\7-Zip\\7z.exe"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .map(Self::new)
    }

    fn command(&self, args: &[&str], archive: &Path) -> Command {
        let mut c = Command::new(&self.exe);
        // An explicit empty password keeps 7-Zip from prompting on encrypted archives.
        c.args(args).arg("-sccUTF-8").arg("-p").arg("-y").arg(archive).stdin(Stdio::null()).stderr(Stdio::null());
        c
    }

    /// `7z l -slt`: one entry per `Path = ...` block after the `----------` line.
    pub(crate) fn list(&self, archive: &Path) -> Result<Vec<ArchiveEntry>> {
        let out = self.command(&["l", "-slt"], archive).output()?;
        let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
        let body = text.split_once("\n----------").map(|(_, b)| b).ok_or_else(|| Error::format("7z: no listing"))?;
        let mut entries = Vec::new();
        for block in body.split("\n\n").filter(|b| b.contains("Path = ")) {
            let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).map(str::to_string);
            let Some(path) = field("Path = ") else { continue };
            let mut e = ArchiveEntry::new(entries.len(), path);
            e.size = field("Size = ").and_then(|s| s.parse().ok());
            e.packed = field("Packed Size = ").and_then(|s| s.parse().ok());
            e.is_dir = field("Folder = ").as_deref() == Some("+") || field("Attributes = ").is_some_and(|a| a.starts_with('D'));
            e.encrypted = field("Encrypted = ").as_deref() == Some("+");
            e.mtime = field("Modified = ").and_then(|m| parse_time(&m));
            entries.push(e);
        }
        if entries.is_empty() && !out.status.success() {
            return Err(Error::format("7z could not list the archive"));
        }
        Ok(entries)
    }

    /// `7z x -so`: one member's bytes on stdout, read up to `limit`.
    pub(crate) fn extract(&self, archive: &Path, member: &str, limit: usize) -> Result<MemberData> {
        let mut child = self.command(&["x", "-so"], archive).arg(member).stdout(Stdio::piped()).spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| Error::Other("7z: no stdout".into()))?;
        let out = read_limited(stdout, limit, member);
        if !out.complete {
            let _ = child.kill();
        }
        let status = child.wait()?;
        let mut damage = out.damage;
        if out.complete && !status.success() {
            damage.push(Damage::new(DamageKind::Corrupt, None, format!("{member}: 7-Zip reported errors ({status})")));
        }
        if out.data.is_empty() && !damage.is_empty() {
            return Err(Error::Other(damage.iter().map(|d| d.note()).collect::<Vec<_>>().join("; ")));
        }
        Ok((out.data, damage))
    }
}

/// `2015-08-07 17:21:08.0000000`
fn parse_time(s: &str) -> Option<Timestamp> {
    let (date, time) = s.split_once(' ')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let mut t = time.split(['.', ':']).map(|p| p.parse::<i64>().ok());
    Timestamp::from_civil(d.next()??, d.next()??, d.next()??, t.next()??, t.next()??, t.next()??)
}

/// Any format 7-Zip understands, read through a temp copy.
pub(crate) struct ExternalReader {
    format: ArchiveFormat,
    tool: SevenZipTool,
    copy: TempCopy,
    entries: Vec<ArchiveEntry>,
}

impl ExternalReader {
    pub fn open(format: ArchiveFormat, tool: SevenZipTool, copy: TempCopy) -> Option<Self> {
        let entries = tool.list(copy.path()).ok().filter(|e| !e.is_empty())?;
        Some(Self { format, tool, copy, entries })
    }
}

impl ArchiveReader for ExternalReader {
    fn format(&self) -> ArchiveFormat {
        self.format
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        self.entries.clone()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        if entry.encrypted {
            return Err(Error::Other("encrypted".into()));
        }
        self.tool.extract(self.copy.path(), &entry.path, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listing_time() {
        let t = parse_time("2015-08-07 17:21:08.0000000").unwrap();
        assert_eq!(t.to_string(), "2015-08-07 17:21:08");
        assert!(parse_time("garbage").is_none());
    }
}
