//! NTUSER.DAT: UserAssist, RecentDocs, RunMRU, TypedURLs, ComDlg32, IE start page, search
//! terms, mail/IM account settings.

use super::hive::{Hive, Key};
use super::mru;
use crate::pidl;
use crate::results::{IdentityKind, Recorder};
use crate::text::{filetime_at, rot13, utf16_at};
use strata_kernel::bytes::u32_le;
use strata_timeline::EventKind;

const EXPLORER: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

/// Known-folder GUIDs seen as UserAssist path prefixes (Win7+).
const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "%SystemRoot%\\System32"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "%ProgramFiles%"),
    ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "%ProgramFiles(x86)%"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "%SystemRoot%"),
    ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "%ProgramData%\\Start Menu\\Programs"),
    ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "%AppData%\\Start Menu\\Programs"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned"),
];

pub(crate) struct NtUser<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> NtUser<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    pub fn parse(&self, rec: &mut Recorder) {
        self.user_assist(rec);
        self.recent_docs(rec);
        self.run_mru(rec);
        self.typed_urls(rec);
        self.comdlg32(rec);
        self.start_page(rec);
        self.search_terms(rec);
        self.accounts(rec);
    }

    fn open(&self, path: &str) -> Option<Key> {
        self.hive.open(path)
    }

    fn user_assist(&self, rec: &mut Recorder) {
        let Some(ua) = self.open(&format!("{EXPLORER}\\UserAssist")) else { return };
        for guid in self.hive.subkeys(&ua) {
            let Some(count) = self.hive.subkey(&guid, "Count") else { continue };
            for v in self.hive.values(&count) {
                let name = expand_known_folder(&rot13(&v.name));
                if name.starts_with("UEME_CTL") || name.is_empty() {
                    continue;
                }
                let name = name.strip_prefix("UEME_RUNPATH:").or_else(|| name.strip_prefix("UEME_RUNPIDL:")).unwrap_or(&name).to_string();
                let (runs, last) = match v.data.len() {
                    16 => (u32_le(&v.data, 4).map(|c| c.saturating_sub(5)), filetime_at(&v.data, 8)),
                    72 => (u32_le(&v.data, 4), filetime_at(&v.data, 60)),
                    _ => continue,
                };
                let detail = format!("UserAssist: run count {}", runs.unwrap_or(0));
                rec.emit(last, EventKind::ProgramRun, name, detail);
            }
        }
    }

    fn recent_docs(&self, rec: &mut Recorder) {
        let Some(root) = self.open(&format!("{EXPLORER}\\RecentDocs")) else { return };
        let mut keys = vec![root.clone()];
        keys.extend(self.hive.subkeys(&root));
        for key in keys {
            let names = mru::ordered(self.hive, &key).iter().map(|v| utf16_at(&v.data, 0, v.data.len())).collect();
            let label = if key.name.starts_with('.') { format!("RecentDocs {}", key.name) } else { "RecentDocs".into() };
            mru::emit(rec, &key, names, EventKind::DocumentOpened, &label, "recent_doc");
        }
    }

    fn run_mru(&self, rec: &mut Recorder) {
        let Some(key) = self.open(&format!("{EXPLORER}\\RunMRU")) else { return };
        let cmds = mru::ordered(self.hive, &key)
            .iter()
            .filter_map(|v| v.string())
            .map(|s| s.trim_end_matches("\\1").to_string())
            .collect();
        mru::emit(rec, &key, cmds, EventKind::ProgramRun, "RunMRU (Start > Run)", "run_mru");
    }

    fn typed_urls(&self, rec: &mut Recorder) {
        let Some(key) = self.open("Software\\Microsoft\\Internet Explorer\\TypedURLs") else { return };
        let times = self.open("Software\\Microsoft\\Internet Explorer\\TypedURLsTime");
        let mut values = self.hive.values(&key);
        values.sort_by_key(|v| v.name.trim_start_matches("url").parse::<u32>().unwrap_or(u32::MAX));
        for (i, v) in values.iter().enumerate() {
            let Some(url) = v.string() else { continue };
            let typed_at = times.as_ref().and_then(|t| self.hive.value(t, &v.name)).and_then(|t| filetime_at(&t.data, 0));
            match (typed_at, i) {
                (Some(at), _) => rec.emit(Some(at), EventKind::UrlVisited, url, "IE TypedURLs (TypedURLsTime)"),
                (None, 0) => rec.emit(key.last_write, EventKind::UrlVisited, url, "IE TypedURLs (most recent; key last write)"),
                (None, _) => rec.fact("typed_url", url),
            }
        }
    }

    fn comdlg32(&self, rec: &mut Recorder) {
        let base = format!("{EXPLORER}\\ComDlg32");
        // XP: per-extension string MRUs.
        if let Some(osm) = self.open(&format!("{base}\\OpenSaveMRU")) {
            for key in std::iter::once(osm.clone()).chain(self.hive.subkeys(&osm)) {
                let paths = mru::ordered(self.hive, &key).iter().filter_map(|v| v.string()).collect();
                mru::emit(rec, &key, paths, EventKind::DocumentOpened, "Open/Save dialog", "opensave_mru");
            }
        }
        // Vista+: PIDL MRUs.
        if let Some(osp) = self.open(&format!("{base}\\OpenSavePidlMRU")) {
            for key in std::iter::once(osp.clone()).chain(self.hive.subkeys(&osp)) {
                let paths = mru::ordered(self.hive, &key).iter().map(|v| pidl::decode(&v.data)).collect();
                mru::emit(rec, &key, paths, EventKind::DocumentOpened, "Open/Save dialog", "opensave_mru");
            }
        }
        for (name, pidl) in [("LastVisitedMRU", false), ("LastVisitedPidlMRU", true)] {
            let Some(key) = self.open(&format!("{base}\\{name}")) else { continue };
            let items = mru::ordered(self.hive, &key).iter().map(|v| last_visited(&v.data, pidl)).collect();
            mru::emit(rec, &key, items, EventKind::ProgramRun, "Open/Save dialog last folder", "last_visited_mru");
        }
    }

    fn start_page(&self, rec: &mut Recorder) {
        let Some(key) = self.open("Software\\Microsoft\\Internet Explorer\\Main") else { return };
        if let Some(page) = self.hive.value(&key, "Start Page").and_then(|v| v.string()) {
            rec.fact("ie_start_page", page.clone());
            rec.push_low(key.last_write, EventKind::Other, format!("IE start page: {page}"), "key last write");
        }
    }

    fn search_terms(&self, rec: &mut Recorder) {
        if let Some(key) = self.open(&format!("{EXPLORER}\\WordWheelQuery")) {
            let terms = mru::ordered(self.hive, &key).iter().map(|v| utf16_at(&v.data, 0, v.data.len())).collect();
            mru::emit(rec, &key, terms, EventKind::Search, "Explorer search (WordWheelQuery)", "search_term");
        }
        if let Some(acmru) = self.open("Software\\Microsoft\\Search Assistant\\ACMru") {
            for key in self.hive.subkeys(&acmru) {
                let mut values = self.hive.values(&key);
                values.sort_by(|a, b| a.name.cmp(&b.name));
                let terms = values.iter().filter_map(|v| v.string()).collect();
                let label = format!("XP search assistant ACMru\\{}", key.name);
                mru::emit(rec, &key, terms, EventKind::Search, &label, "search_term");
            }
        }
    }

    /// Outlook Express / Windows Mail accounts and ICQ owners.
    fn accounts(&self, rec: &mut Recorder) {
        if let Some(accts) = self.open("Software\\Microsoft\\Internet Account Manager\\Accounts") {
            for key in self.hive.subkeys(&accts) {
                for (value, kind) in [("SMTP Email Address", IdentityKind::Email), ("POP3 User Name", IdentityKind::Login), ("IMAP User Name", IdentityKind::Login)] {
                    if let Some(s) = self.hive.value(&key, value).and_then(|v| v.string()) {
                        let server = self.hive.value(&key, "POP3 Server").and_then(|v| v.string());
                        rec.identity(kind, &s, server.as_deref(), key.last_write);
                        rec.emit(key.last_write, EventKind::AccountSeen, s, format!("mail account ({value})"));
                    }
                }
            }
        }
        if let Some(owners) = self.open("Software\\Mirabilis\\ICQ\\NewOwners") {
            for key in self.hive.subkeys(&owners) {
                rec.identity(IdentityKind::Nickname, &key.name, Some("ICQ"), key.last_write);
            }
        }
    }
}

/// `{GUID}\rest` → `%Folder%\rest`.
fn expand_known_folder(name: &str) -> String {
    for (guid, folder) in KNOWN_FOLDERS {
        if let Some(rest) = name.get(..guid.len()).filter(|p| p.eq_ignore_ascii_case(guid)).and(name.get(guid.len()..)) {
            return format!("{folder}{rest}");
        }
    }
    name.to_string()
}

/// LastVisited entries: UTF-16 executable name, then a UTF-16 path (XP) or a PIDL (Vista+).
fn last_visited(data: &[u8], pidl: bool) -> String {
    let exe = utf16_at(data, 0, data.len());
    let rest = 2 * exe.encode_utf16().count() + 2;
    let folder = if pidl { pidl::decode(data.get(rest..).unwrap_or(&[])) } else { utf16_at(data, rest, data.len()) };
    format!("{exe} → {folder}")
}
