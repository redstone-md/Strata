//! Filesystem MACB times of every entry as timeline events (lazy: a disk has millions).

use super::profile_of;
use crate::tag::Tagger;
use strata_fs::{FileEntry, FileSystem};
use strata_kernel::Timestamp;
use strata_timeline::{EventKind, EventSource, TimelineEvent};

/// Iterator over MACB events; deleted and orphan entries are marked `source.deleted`.
pub struct FsEvents<'a> {
    entries: std::slice::Iter<'a, FileEntry>,
    pending: Vec<TimelineEvent>,
}

/// MACB events for every entry of `fs`. Bound it with `.take(n)` or filter lazily.
pub fn fs_events(fs: &dyn FileSystem) -> FsEvents<'_> {
    FsEvents { entries: fs.entries().iter(), pending: Vec::new() }
}

impl FsEvents<'_> {
    fn expand(entry: &FileEntry) -> Vec<TimelineEvent> {
        let t = &entry.times;
        let stamps: [(Option<Timestamp>, EventKind); 4] = [
            (t.changed, EventKind::MftChanged),
            (t.accessed, EventKind::FileAccessed),
            (t.modified, EventKind::FileModified),
            (t.created, EventKind::FileCreated),
        ];
        if stamps.iter().all(|(s, _)| s.is_none()) {
            return Vec::new();
        }
        let source = EventSource { artifact: "fs".to_string(), path: entry.path.clone(), deleted: entry.is_deleted() };
        let tags = Tagger::shared().tags_for(&entry.path);
        let actor = profile_of(&entry.path);
        let detail = format!("{} bytes{}{}", entry.size, if entry.is_dir { "; directory" } else { "" }, state(entry));
        stamps
            .into_iter()
            .filter_map(|(at, kind)| {
                let mut e = TimelineEvent::new(at?, kind, entry.path.clone(), source.clone()).with_detail(detail.clone());
                for tag in &tags {
                    e.add_tag(tag.clone());
                }
                if let Some(a) = &actor {
                    e.set_actor(a.clone());
                }
                Some(e)
            })
            .collect()
    }
}

fn state(entry: &FileEntry) -> &'static str {
    match entry.state {
        strata_fs::EntryState::Allocated => "",
        strata_fs::EntryState::Deleted => "; deleted",
        strata_fs::EntryState::Orphan => "; orphan",
    }
}

impl Iterator for FsEvents<'_> {
    type Item = TimelineEvent;

    fn next(&mut self) -> Option<TimelineEvent> {
        loop {
            if let Some(e) = self.pending.pop() {
                return Some(e);
            }
            self.pending = Self::expand(self.entries.next()?);
        }
    }
}
