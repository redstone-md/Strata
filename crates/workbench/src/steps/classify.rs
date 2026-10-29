//! Content-based type of every file: catches renamed extensions (a wallet saved as `.jpg`)
//! and tells what damaged files still are. Types are stored in batches together with the
//! cursor `(volume, next file)`, so a resumed run continues at the next unclassified file.

use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_case::{Attribution, FileRef};
use strata_fs::{ExtentReader, FileEntry};
use strata_identify::{Identifier, TypeVerdict};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Result};
use strata_source::BlockSource;
use strata_volume::Volume;

/// Head bytes read per file; enough for headers, directories and structure probes.
const HEAD_BYTES: usize = 1 << 20;

/// Extensions of plain user documents: random bytes behind these are worth a look
/// (encrypted containers, wallets saved as text files). Random bytes behind media or
/// binaries are normal compression or overwritten clusters.
const PLAIN_DOCUMENTS: &[&str] = &["txt", "doc", "rtf", "csv", "ini", "log", "xml", "htm", "html", "dat", "bak"];

type TypeRow = (u32, usize, String, bool, String);

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClassifyCursor {
    /// Volumes classified completely.
    volumes: Vec<u32>,
    /// Volume in progress and the index of its next file.
    volume: Option<u32>,
    next_file: usize,
    classified: usize,
    flagged: usize,
}

impl Cursor for ClassifyCursor {
    fn note(&self) -> String {
        match self.volume {
            Some(v) => format!("volume {v}, file {} ({} files classified)", self.next_file, self.classified),
            None if self.volumes.is_empty() => "the first file".into(),
            None => format!("after volume {} ({} files classified)", super::list(&self.volumes), self.classified),
        }
    }
}

/// Content we read may not be the file's own: deleted files whose clusters were reused,
/// or extents over unreadable sectors. Such files and headerless random data behind
/// media/binary extensions produced ~1,400 false alarms on a 40 GB test disk.
fn worth_reporting(e: &FileEntry, v: &TypeVerdict) -> bool {
    if !e.damage.is_empty() {
        return false;
    }
    // Hidden valuables are wallets, databases, archives, documents, mail — not programs.
    if v.category == strata_identify::Category::Executable {
        return false;
    }
    let path = e.path.to_ascii_lowercase();
    let in_system = ["windows/", "winnt/", "program files/", "program files (x86)/"].iter().any(|p| path.starts_with(p));
    if in_system && !matches!(v.category, strata_identify::Category::Wallet | strata_identify::Category::Database) {
        return false;
    }
    if v.method == strata_identify::Method::Entropy {
        let ext = e.extension().unwrap_or_default().to_ascii_lowercase();
        return e.state == strata_fs::EntryState::Allocated && PLAIN_DOCUMENTS.contains(&ext.as_str());
    }
    true
}

/// Type row of one file, plus a finding when its extension hides what it is.
fn classify(identifier: &Identifier, vol: &Volume, source: &dyn BlockSource, idx: usize, e: &FileEntry) -> Option<(TypeRow, Option<(Hit, Attribution)>)> {
    if e.size == 0 {
        return None;
    }
    let head = ExtentReader::new(source, e).read_all(HEAD_BYTES).ok()?;
    let v = identifier.identify(&head, Some(&e.name));
    let mismatch = v.extension_mismatch.as_ref();
    let notes = mismatch.map(|m| m.reason.clone()).unwrap_or_default();
    let flag = mismatch.filter(|m| m.suspicious && worth_reporting(e, &v)).map(|m| {
        let offset = vol.range.start() + e.extents.first().and_then(|x| x.volume_offset).unwrap_or(0);
        let confidence = if v.confidence.get() > Confidence::MEDIUM.get() { v.confidence } else { Confidence::MEDIUM };
        let hit = Hit::new("identify.mismatch", HitCategory::FileSignature, offset, head.len())
            .label(format!("{} disguised as .{}", v.type_name, m.declared))
            .value(e.path.clone())
            .confidence(confidence)
            .details(serde_json::to_value(&v).unwrap_or_default());
        let file = FileRef { path: e.path.clone(), state: e.state, file_offset: 0 };
        (hit, Attribution { volume: Some(vol.index), file: Some(file) })
    });
    Some(((vol.index, idx, v.type_name.clone(), mismatch.is_some(), notes), flag))
}

/// Rows and findings waiting for the next commit.
#[derive(Default)]
struct Batch {
    rows: Vec<TypeRow>,
    flagged: Vec<(Hit, Attribution)>,
}

impl Batch {
    fn commit(&mut self, ctx: &StepContext<'_>, cur: &mut ClassifyCursor) -> Result<()> {
        cur.classified += self.rows.len();
        cur.flagged += self.flagged.len();
        let id = ctx.evidence();
        let (rows, flagged) = (std::mem::take(&mut self.rows), std::mem::take(&mut self.flagged));
        ctx.commit(cur, |w| {
            w.file_types(id, &rows)?;
            w.hits(id, &flagged)
        })?;
        Ok(())
    }
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let source = ctx.source()?;
    let layout = ctx.case().layout(ctx.evidence())?;
    let identifier = Identifier::new();
    let mut cur: ClassifyCursor = ctx.cursor().unwrap_or_default();
    let files = |fs: &dyn strata_fs::FileSystem, upto: usize| fs.entries().iter().take(upto).filter(|e| !e.is_dir).count() as u64;
    let (mut done, mut total) = (0, 0);
    for (vol, fs) in layout.filesystems() {
        let all = files(fs, usize::MAX);
        total += all;
        done += if cur.volumes.contains(&vol.index) { all } else if cur.volume == Some(vol.index) { files(fs, cur.next_file) } else { 0 };
    }
    ctx.control().begin_at(done, total);
    let mut batch = Batch::default();
    'volumes: for (vol, fs) in layout.filesystems() {
        if cur.volumes.contains(&vol.index) {
            continue;
        }
        let start = if cur.volume == Some(vol.index) { cur.next_file } else { 0 };
        cur.volume = Some(vol.index);
        let vol_source = vol.open(source.clone());
        for (idx, e) in fs.entries().iter().enumerate().skip(start) {
            if e.is_dir {
                continue;
            }
            if ctx.should_stop() {
                break 'volumes;
            }
            ctx.current(&e.path);
            if let Some((row, flag)) = classify(&identifier, vol, vol_source.as_ref(), idx, e) {
                batch.rows.push(row);
                batch.flagged.extend(flag);
            }
            cur.next_file = idx + 1;
            ctx.control().item_done();
            if ctx.tick(1) {
                batch.commit(ctx, &mut cur)?;
            }
        }
        cur.volumes.push(vol.index);
        cur.volume = None;
        cur.next_file = 0;
        ctx.log(format!("volume {}: {} files classified so far, {} suspicious", vol.index, cur.classified + batch.rows.len(), cur.flagged + batch.flagged.len()));
    }
    batch.commit(ctx, &mut cur)?;
    Ok(format!("{} files, {} suspicious renames", cur.classified, cur.flagged))
}
