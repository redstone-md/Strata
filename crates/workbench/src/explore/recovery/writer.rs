//! Writes recovered content into a destination folder and logs every file to
//! `recovery-log.csv` (path, state, size, bytes recovered, damage, SHA-256, written to).
//!
//! The destination may never be the folder an evidence image lives in (or inside it): a
//! recovery must not land next to the evidence it came from.

use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use strata_kernel::{Error, Result};

pub const LOG_NAME: &str = "recovery-log.csv";
const BLOCK: usize = 1 << 20;
const PARTIAL_SUFFIX: &str = ".partial";

/// What is known about an item before its bytes are copied.
pub struct Item {
    /// Path on the evidence (shown in the log).
    pub source_path: String,
    /// `live`, `deleted`, `orphan`, `carved`, `archive member`...
    pub state: String,
    pub size: u64,
    /// Bytes believed to be the item's own (overwritten or missing parts excluded).
    pub intact: u64,
    pub damage: Vec<String>,
}

impl Item {
    pub fn is_partial(&self) -> bool {
        !self.damage.is_empty() || self.intact < self.size
    }
}

/// One written file, as logged.
#[derive(Debug, Clone)]
pub struct Recovered {
    pub written_to: PathBuf,
    pub bytes_written: u64,
    pub partial: bool,
    pub sha256: String,
}

pub struct RecoveryWriter {
    root: PathBuf,
    log: BufWriter<File>,
    /// The next item replaces a file of the same name instead of getting a new name: a
    /// resumed job rewrites the item an interrupted run may have written already.
    replace_next: bool,
}

impl RecoveryWriter {
    /// Open `dest` (created if missing) after checking it is not beside any evidence file.
    pub fn open(dest: &Path, evidence_locations: &[String]) -> Result<Self> {
        std::fs::create_dir_all(dest)?;
        let root = dest.canonicalize()?;
        for location in evidence_locations {
            let Some(folder) = Path::new(location).parent().and_then(|p| p.canonicalize().ok()) else { continue };
            if root.starts_with(&folder) {
                return Err(Error::Other(format!(
                    "{} is next to the evidence {location}; pick a folder elsewhere",
                    dest.display()
                )));
            }
        }
        let log_path = root.join(LOG_NAME);
        let new = !log_path.exists();
        let mut log = BufWriter::new(OpenOptions::new().create(true).append(true).open(&log_path)?);
        if new {
            writeln!(log, "path,state,size,bytes_recovered,damage,sha256,written_to")?;
        }
        Ok(Self { root, log, replace_next: false })
    }

    /// Let the next written item replace an existing file of the same name.
    pub fn replace_next(&mut self) {
        self.replace_next = true;
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create a directory (and its parents) under the destination.
    pub fn directory(&self, components: &[String]) -> Result<PathBuf> {
        let dir = components.iter().fold(self.root.clone(), |p, c| p.join(sanitize(c)));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Copy one item to `components` (sanitised; `.partial` added when damaged) through
    /// `read(offset, buf)`, hash it and log it.
    pub fn write(&mut self, components: &[String], item: &Item, read: &mut dyn FnMut(u64, &mut [u8]) -> Result<usize>) -> Result<Recovered> {
        let (name, parents) = components.split_last().ok_or_else(|| Error::Other("empty path".into()))?;
        let dir = self.directory(parents)?;
        let partial = item.is_partial();
        let mut name = sanitize(name);
        if partial {
            name.push_str(PARTIAL_SUFFIX);
        }
        let path = if std::mem::take(&mut self.replace_next) { dir.join(name) } else { unique(dir.join(name)) };
        let mut out = BufWriter::new(File::create(&path)?);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; BLOCK];
        let mut done = 0u64;
        while done < item.size {
            let want = ((item.size - done) as usize).min(BLOCK);
            let n = read(done, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            done += n as u64;
        }
        out.flush()?;
        let sha256: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let row = [
            item.source_path.clone(),
            item.state.clone(),
            item.size.to_string(),
            item.intact.min(done).to_string(),
            item.damage.join("; "),
            sha256.clone(),
            path.display().to_string(),
        ];
        writeln!(self.log, "{}", row.iter().map(|f| csv(f)).collect::<Vec<_>>().join(","))?;
        Ok(Recovered { written_to: path, bytes_written: done, partial, sha256 })
    }

    pub fn finish(mut self) -> Result<()> {
        self.log.flush()?;
        Ok(())
    }
}

fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) { format!("\"{}\"", field.replace('"', "\"\"")) } else { field.to_string() }
}

/// `name`, or `name (2)`, `name (3)`... when taken.
fn unique(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let stem = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    (2..).map(|i| path.with_file_name(format!("{stem} ({i})"))).find(|p| !p.exists()).unwrap_or(path)
}

/// A path component safe on Windows: no separators, reserved characters, `.`/`..`,
/// device names or trailing dots and spaces.
pub fn sanitize(component: &str) -> String {
    let mut s: String = component.chars().map(|c| if c < ' ' || r#"<>:"/\|?*"#.contains(c) { '_' } else { c }).collect();
    while s.ends_with(['.', ' ']) {
        s.pop();
    }
    let stem = s.split('.').next().unwrap_or_default().to_ascii_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.ends_with(|c: char| c.is_ascii_digit()));
    if s.is_empty() || reserved {
        s.insert(0, '_');
    }
    s.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitises_names() {
        assert_eq!(sanitize("a:b?.txt"), "a_b_.txt");
        assert_eq!(sanitize(".."), "_");
        assert_eq!(sanitize("con.txt"), "_con.txt");
        assert_eq!(sanitize("$Orphans"), "$Orphans");
        assert_eq!(sanitize("x. "), "x");
    }

    #[test]
    fn refuses_the_evidence_folder() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        std::fs::write(&image, b"x").unwrap();
        let evidence = vec![image.display().to_string()];
        assert!(RecoveryWriter::open(&dir.path().join("out"), &evidence).is_err());
        let other = tempfile::tempdir().unwrap();
        assert!(RecoveryWriter::open(other.path(), &evidence).is_ok());
    }
}
