//! Which parser a file goes to: by path (filesystem walk) or by content (carved bytes).

use crate::configs::{MinerConfig, MozillaPrefs, OeAccount};
use crate::browser::{self, FirefoxLogins, IndexDat, OperaGlobalHistory, OperaTypedHistory};
use crate::mail::{Dbx, Mailbox};
use strata_mail::Container;
use crate::registry::{self, RegistryHive};
use crate::results::{ArtifactResults, Recorder};
use crate::linux::{LinuxSystem, RecentlyUsed, ShellHistory, WalletDir, Wtmp};
use crate::windows::{EventLog, Evtx, Info2, Lnk, Prefetch, RecycleI};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// Chrome/Opera/Yandex/Edge History, Login Data, Web Data, Cookies; Firefox *.sqlite.
    BrowserSqlite,
    FirefoxLoginsJson,
    IeIndexDat,
    OperaTypedHistory,
    OperaGlobalHistory,
    RegistryHive,
    Lnk,
    Prefetch,
    RecycleInfo2,
    RecycleI,
    EventLog,
    /// Vista+ `.evtx` log, or carved `ElfChnk` chunks.
    Evtx,
    OutlookDbx,
    Mailbox,
    /// bash / zsh history.
    ShellHistory,
    /// GNOME `recently-used.xbel`.
    RecentlyUsed,
    /// `/var/log/wtmp` logins.
    Wtmp,
    /// `/var/log/btmp` failed logins.
    Btmp,
    /// Files inside a wallet program's data folder (`~/.bitcoin/debug.log`...).
    WalletDir,
    /// Mozilla `prefs.js` (Thunderbird identities, Firefox Sync).
    MozillaPrefs,
    /// Windows Live Mail `.oeaccount`.
    OeAccount,
    /// Mining software config or launch script naming a pool login.
    MinerConfig,
    /// Linux system configuration: `/etc/hostname`, `os-release`, `passwd`, time zone,
    /// NetworkManager connections, DHCP leases.
    LinuxSystem,
}

/// Mining software config file names.
const MINER_CONFIGS: &[&str] = &["cgminer.conf", "bfgminer.conf", "sgminer.conf", "poclbm.ini", "guiminer.ini", "ccminer.conf", "config.json"];

/// Chromium-family database file names (no extension).
const CHROMIUM_DBS: &[&str] = &["history", "archived history", "login data", "web data", "cookies"];
/// Path fragments of Chromium-family profiles.
const CHROMIUM_DIRS: &[&str] = &[
    "/user data/", "opera software/", "/yandex/", "/chrome/", "/chromium/", "/edge/", "/opera stable/",
    "/google-chrome/", "/yandex-browser/", "/microsoft-edge/", "/vivaldi/", "/bravesoftware/", "/opera/",
];
const FIREFOX_DBS: &[&str] = &["places.sqlite", "formhistory.sqlite", "cookies.sqlite", "signons.sqlite", "downloads.sqlite"];
const HIVE_NAMES: &[&str] = &["system", "software", "sam"];

impl ArtifactKind {
    /// Classify by path (`/`-separated, any case).
    pub fn from_path(path: &str) -> Option<Self> {
        let p = format!("/{}", path.to_lowercase().replace('\\', "/"));
        let name = p.rsplit('/').next().unwrap_or("");
        let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
        let under = |dir: &str| p.contains(dir);
        let mail = Container::by_name(&p);
        Some(match name {
            n if CHROMIUM_DBS.contains(&n) && CHROMIUM_DIRS.iter().any(|d| under(d)) => Self::BrowserSqlite,
            n if FIREFOX_DBS.contains(&n) => Self::BrowserSqlite,
            "logins.json" => Self::FirefoxLoginsJson,
            "index.dat" => Self::IeIndexDat,
            "typed_history.xml" => Self::OperaTypedHistory,
            "global_history.dat" | "global.dat" if under("opera") => Self::OperaGlobalHistory,
            "ntuser.dat" | "usrclass.dat" => Self::RegistryHive,
            n if HIVE_NAMES.contains(&n) && (under("/system32/config/") || under("/repair/")) => Self::RegistryHive,
            n if n.starts_with("_registry_machine_") || n.starts_with("_registry_user_ntuser") => Self::RegistryHive,
            "info2" if under("/recycler/") || under("/recycled/") => Self::RecycleInfo2,
            n if n.starts_with("$i") && under("/$recycle.bin/") => Self::RecycleI,
            _ if ext == "lnk" && (under("/recent/") || under("/desktop/")) => Self::Lnk,
            _ if ext == "pf" && under("/prefetch/") => Self::Prefetch,
            _ if ext == "evt" => Self::EventLog,
            _ if ext == "evtx" => Self::Evtx,
            _ if mail == Some(Container::Dbx) => Self::OutlookDbx,
            _ if mail.is_some() => Self::Mailbox,
            ".bash_history" | ".zsh_history" | ".history" | ".sh_history" => Self::ShellHistory,
            "recently-used.xbel" | ".recently-used.xbel" => Self::RecentlyUsed,
            n if (n == "wtmp" || n.starts_with("wtmp.")) && under("/var/log/") => Self::Wtmp,
            n if (n == "btmp" || n.starts_with("btmp.")) && under("/var/log/") => Self::Btmp,
            "prefs.js" if ["/mozilla/", "/thunderbird/", "/.thunderbird/", "/firefox/", "/.mozilla/"].iter().any(|d| under(d)) => Self::MozillaPrefs,
            _ if ext == "oeaccount" => Self::OeAccount,
            n if MINER_CONFIGS.contains(&n) && (n != "config.json" || ["miner", "xmrig"].iter().any(|d| under(d))) => Self::MinerConfig,
            _ if matches!(ext, "bat" | "cmd") && !under("/windows/") => Self::MinerConfig,
            _ if LinuxSystem::matches(&p) => Self::LinuxSystem,
            _ if crate::linux::WalletDir::software(&p).is_some() && (name == "debug.log" || matches!(ext, "conf" | "json" | "config")) => Self::WalletDir,
            _ => return None,
        })
    }

    /// Classify by an unambiguous file signature only.
    pub fn sniff_magic(data: &[u8]) -> Option<Self> {
        Some(if crate::sqlite::is_sqlite(data) {
            Self::BrowserSqlite
        } else if RegistryHive::is_regf(data) {
            Self::RegistryHive
        } else if IndexDat::is_index_dat(data) {
            Self::IeIndexDat
        } else if Lnk::is_lnk(data) {
            Self::Lnk
        } else if Prefetch::is_prefetch(data) {
            Self::Prefetch
        } else if EventLog::is_evt(data) {
            Self::EventLog
        } else if Evtx::is_evtx(data) {
            Self::Evtx
        } else if Dbx::is_dbx(data) {
            Self::OutlookDbx
        } else {
            return None;
        })
    }

    /// Classify carved bytes by signature, then content hints, then the name hint.
    pub fn sniff(name_hint: &str, data: &[u8]) -> Option<Self> {
        if let Some(kind) = Self::sniff_magic(data) {
            return Some(kind);
        }
        let head = &data[..data.len().min(4096)];
        let text = String::from_utf8_lossy(head);
        let hint = name_hint.to_ascii_lowercase();
        let file_name = hint.rsplit(['/', '\\']).next().unwrap_or("");
        Some(if text.contains("<typed_history") {
            Self::OperaTypedHistory
        } else if text.contains("\"encryptedUsername\"") || file_name == "logins.json" {
            Self::FirefoxLoginsJson
        } else if file_name == "info2" {
            Self::RecycleInfo2
        } else if RecycleI::is_i_file(data) && file_name.starts_with("$i") {
            Self::RecycleI
        } else if file_name.contains("global_history") || file_name == "global.dat" {
            Self::OperaGlobalHistory
        } else if Mailbox::looks_like_mail(data) {
            Self::Mailbox
        } else if MozillaPrefs::looks_like(&text) {
            Self::MozillaPrefs
        } else if OeAccount::looks_like(&crate::configs::config_text(head)) {
            Self::OeAccount
        } else if text.contains("stratum+tcp://") && MinerConfig::looks_like(&text) {
            Self::MinerConfig
        } else {
            return Self::from_path(name_hint);
        })
    }

    /// Size cap per kind (larger files are truncated before parsing).
    pub(crate) fn max_size(self) -> u64 {
        match self {
            Self::Lnk | Self::RecycleI | Self::Prefetch | Self::OperaTypedHistory | Self::FirefoxLoginsJson => 16 << 20,
            Self::MozillaPrefs | Self::OeAccount => 4 << 20,
            Self::MinerConfig => 64 << 10,
            Self::LinuxSystem => 1 << 20,
            Self::RegistryHive | Self::BrowserSqlite | Self::IeIndexDat => 512 << 20,
            _ => 256 << 20,
        }
    }

    /// Run the parser. `name_hint` steers damaged-SQLite fallbacks.
    pub fn parse(self, name_hint: &str, data: &[u8]) -> ArtifactResults {
        let one = |artifact: &'static str, f: &dyn Fn(&mut Recorder)| {
            let mut rec = Recorder::new(artifact);
            f(&mut rec);
            rec.finish()
        };
        match self {
            Self::BrowserSqlite => browser::parse_sqlite(name_hint, data),
            Self::RegistryHive => registry::parse_hive(data),
            Self::FirefoxLoginsJson => one("firefox.logins", &|r| FirefoxLogins::parse_json(data, r)),
            Self::IeIndexDat => one("ie.index_dat", &|r| IndexDat::new(data).parse(r)),
            Self::OperaTypedHistory => one("opera.typed_history", &|r| OperaTypedHistory::parse(data, r)),
            Self::OperaGlobalHistory => one("opera.global_history", &|r| OperaGlobalHistory::parse(data, r)),
            Self::Lnk => one("windows.lnk", &|r| {
                Lnk::parse(data, r);
            }),
            Self::Prefetch => one("windows.prefetch", &|r| Prefetch::parse(data, r)),
            Self::RecycleInfo2 => one("windows.recycle_info2", &|r| Info2::parse(data, r)),
            Self::RecycleI => one("windows.recycle_i", &|r| RecycleI::parse(data, r)),
            Self::EventLog => one("windows.evt", &|r| EventLog::parse(data, r)),
            Self::Evtx => one("windows.evtx", &|r| Evtx::parse(data, r)),
            Self::OutlookDbx => one("mail.outlook_express", &|r| Dbx::parse(data, r)),
            Self::Mailbox => one("mail.mbox", &|r| Mailbox::parse(data, r)),
            Self::ShellHistory => one("linux.shell_history", &|r| ShellHistory::parse(data, r)),
            Self::RecentlyUsed => one("linux.recently_used", &|r| RecentlyUsed::parse(data, r)),
            Self::Wtmp => one("linux.wtmp", &|r| Wtmp::parse(data, false, r)),
            Self::Btmp => one("linux.btmp", &|r| Wtmp::parse(data, true, r)),
            Self::WalletDir => one("linux.wallet_dir", &|r| WalletDir::parse(name_hint, data, r)),
            Self::MozillaPrefs => one("mozilla.prefs", &|r| MozillaPrefs::parse(data, r)),
            Self::OeAccount => one("mail.oeaccount", &|r| OeAccount::parse(data, r)),
            Self::MinerConfig => one("miner.config", &|r| MinerConfig::parse(data, r)),
            Self::LinuxSystem => one("linux.system", &|r| LinuxSystem::parse(name_hint, data, r)),
        }
    }

    /// Config files carry no dates: their identities are dated by the file's own times.
    pub(crate) fn dated_by_file(self) -> bool {
        matches!(self, Self::MozillaPrefs | Self::OeAccount | Self::MinerConfig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        let k = ArtifactKind::from_path;
        let xp = "Documents and Settings/Admin/Local Settings/Application Data";
        assert_eq!(k(&format!("{xp}/Google/Chrome/User Data/Default/History")), Some(ArtifactKind::BrowserSqlite));
        assert_eq!(k(&format!("{xp}/Google/Chrome/User Data/Default/Login Data")), Some(ArtifactKind::BrowserSqlite));
        assert_eq!(k("Users/a/AppData/Roaming/Opera Software/Opera Stable/History"), Some(ArtifactKind::BrowserSqlite));
        assert_eq!(k("Documents and Settings/Admin/Application Data/Mozilla/Firefox/Profiles/x.default/places.sqlite"), Some(ArtifactKind::BrowserSqlite));
        assert_eq!(k("Documents and Settings/Admin/Local Settings/History/History.IE5/MSHist012011121520111216/index.dat"), Some(ArtifactKind::IeIndexDat));
        assert_eq!(k("WINDOWS/system32/config/SYSTEM"), Some(ArtifactKind::RegistryHive));
        assert_eq!(k("WINDOWS/system32/config/system.LOG"), None);
        assert_eq!(k("Documents and Settings/Admin/NTUSER.DAT"), Some(ArtifactKind::RegistryHive));
        assert_eq!(k("Users/a/AppData/Local/Microsoft/Windows/UsrClass.dat"), Some(ArtifactKind::RegistryHive));
        let xp_classes = "Documents and Settings/a/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat";
        assert_eq!(k(xp_classes), Some(ArtifactKind::RegistryHive));
        assert_eq!(k("WINDOWS/Prefetch/BITCOIN.EXE-1A2B3C4D.pf"), Some(ArtifactKind::Prefetch));
        assert_eq!(k("RECYCLER/S-1-5-21-1/INFO2"), Some(ArtifactKind::RecycleInfo2));
        assert_eq!(k("$Recycle.Bin/S-1-5-21-1/$IAB12CD.dat"), Some(ArtifactKind::RecycleI));
        assert_eq!(k("Documents and Settings/Admin/Recent/wallet.dat.lnk"), Some(ArtifactKind::Lnk));
        assert_eq!(k("Program Files/Google/Chrome/History"), Some(ArtifactKind::BrowserSqlite));
        assert_eq!(k("Program Files/app/History"), None);
        assert_eq!(k("Windows/System32/winevt/Logs/Security.evtx"), Some(ArtifactKind::Evtx));
        assert_eq!(k("Windows/System32/winevt/Logs/Security.evtx.bak"), None);
        assert_eq!(k("Users/a/AppData/Roaming/Thunderbird/Profiles/x.default/prefs.js"), Some(ArtifactKind::MozillaPrefs));
        assert_eq!(k("Users/a/AppData/Local/Microsoft/Windows Live Mail/mail.ru/account{1}.oeaccount"), Some(ArtifactKind::OeAccount));
        assert_eq!(k("Program Files/cgminer/cgminer.conf"), Some(ArtifactKind::MinerConfig));
        assert_eq!(k("Users/a/Desktop/start_mining.bat"), Some(ArtifactKind::MinerConfig));
        assert_eq!(k("Windows/System32/setup.bat"), None);
        assert_eq!(k("Users/a/Documents/config.json"), None);
        assert_eq!(k("etc/hostname"), Some(ArtifactKind::LinuxSystem));
        assert_eq!(k("var/lib/docker/overlay2/ab12/diff/etc/os-release"), Some(ArtifactKind::LinuxSystem));
        assert_eq!(k("Windows/System32/drivers/etc/hosts"), None);
    }
}
