//! Shellbags: the folders a user browsed in Explorer, kept as a `BagMRU` tree of shell items in
//! NTUSER.DAT (XP: `Shell` / `ShellNoRoam`) and UsrClass.dat (Vista+). Every node's values are
//! single shell items; its numbered subkeys hold the children of the matching value.
//!
//! Dating: a node's last write is when its MRU order last changed, i.e. when the newest entry
//! (first in `MRUListEx`) was opened. Older entries become undated facts. File-entry items also
//! carry the folder's own modified/created/accessed times, emitted at low confidence.

use super::hive::{Hive, Key};
use super::mru;
use crate::pidl::{self, ItemKind, ShellItem};
use crate::results::{ArtifactResults, Recorder};
use strata_kernel::{Confidence, Timestamp};
use strata_timeline::{CRYPTO_TAG, EventKind};

const BAG_ROOTS: &[&str] = &[
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
];
const MAX_DEPTH: usize = 48;
const MAX_FOLDERS: usize = 50_000;
/// Folder-name fragments (lowercase) that mark a wallet folder. Data table.
const WALLET_WORDS: &[&str] =
    &["wallet", "bitcoin", "electrum", "multibit", "armory", "litecoin", "exodus", "blockchain", "кошел", "биткоин"];

pub(crate) const FOLDER_TAG: &str = "folder";
const SHELLBAG_TAG: &str = "shellbag";
const REMOVABLE_TAG: &str = "removable";
const WALLET_FOLDER_TAG: &str = "wallet-folder";

pub(crate) struct ShellBags<'h, 'a> {
    hive: &'h Hive<'a>,
    folders: usize,
}

impl<'h, 'a> ShellBags<'h, 'a> {
    pub(crate) fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive, folders: 0 }
    }

    pub(crate) fn scan(mut self) -> ArtifactResults {
        let mut rec = Recorder::new("registry.shellbags");
        for root in BAG_ROOTS {
            if let Some(key) = self.hive.open(root) {
                self.walk(&mut rec, &key, &[], 0);
            }
        }
        rec.finish()
    }

    fn walk(&mut self, rec: &mut Recorder, key: &Key, parents: &[ShellItem], depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let dated = self.hive.value(key, "MRUListEx").is_some();
        let slots = mru::ordered(self.hive, key).into_iter().filter(|v| v.name.parse::<u32>().is_ok());
        for (rank, value) in slots.enumerate() {
            if self.folders >= MAX_FOLDERS {
                return;
            }
            self.folders += 1;
            let mut chain = parents.to_vec();
            let items = pidl::items(&value.data);
            if items.is_empty() {
                chain.push(ShellItem { name: format!("<unreadable item {}>", value.name), ..ShellItem::default() });
            }
            chain.extend(items);
            pidl::mark_devices(&mut chain);
            let folder = Folder::new(&chain);
            if rank == 0 && dated {
                let detail = "opened in Explorer (shellbag: newest entry of its parent; parent key last write)";
                folder.push(rec, key.last_write, EventKind::DocumentOpened, detail, Confidence::HIGH);
            } else {
                rec.fact("shellbag_folder", folder.path.clone());
            }
            if let Some(last) = chain.last() {
                for (at, kind, what) in [
                    (last.modified, EventKind::FileModified, "modified"),
                    (last.created, EventKind::FileCreated, "created"),
                    (last.accessed, EventKind::FileAccessed, "accessed"),
                ] {
                    folder.push(rec, at, kind, &format!("folder {what} (time stored in the shellbag item)"), Confidence::LOW);
                }
            }
            if let Some(sub) = self.hive.subkey(key, &value.name) {
                self.walk(rec, &sub, &chain, depth + 1);
            }
        }
    }
}

/// A reconstructed folder path and its tags.
struct Folder {
    path: String,
    tags: Vec<String>,
}

impl Folder {
    fn new(chain: &[ShellItem]) -> Self {
        let mut tags = vec![FOLDER_TAG.to_string(), SHELLBAG_TAG.to_string()];
        let lower: Vec<String> = chain.iter().map(|i| i.name.to_lowercase()).collect();
        let drive = chain.iter().find(|i| i.kind == ItemKind::Volume).and_then(|v| v.name.chars().next()).map(|c| c.to_ascii_uppercase());
        let floppy = matches!(drive, Some('A' | 'B'));
        if floppy || chain.iter().any(|i| i.kind == ItemKind::Device) || lower.iter().any(|n| n.contains("usb")) {
            tags.push(REMOVABLE_TAG.to_string());
        }
        if let Some(d) = drive.filter(char::is_ascii_alphabetic) {
            tags.push(format!("drive:{d}"));
        }
        if chain.iter().any(|i| i.kind == ItemKind::Network) {
            tags.push("network".to_string());
        }
        if lower.iter().any(|n| WALLET_WORDS.iter().any(|w| n.contains(w))) {
            tags.push(CRYPTO_TAG.to_string());
            tags.push(WALLET_FOLDER_TAG.to_string());
        }
        Self { path: pidl::join(chain), tags }
    }

    fn push(&self, rec: &mut Recorder, at: Option<Timestamp>, kind: EventKind, detail: &str, confidence: Confidence) {
        let Some(mut event) = rec.make(at, kind, self.path.clone()) else { return };
        event = event.with_detail(detail).with_confidence(confidence);
        for t in &self.tags {
            event.add_tag(t.clone());
        }
        rec.push(event);
    }
}
