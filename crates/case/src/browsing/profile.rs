//! Which browser and which profile folder a browser event came from, read back from the
//! parser's artefact name and the file the event was read from.

use serde::Serialize;
use strata_kernel::EvidenceId;

/// Browser family, decided by the parser that read the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    /// Chrome and every Blink browser (Opera 15+, Yandex, Edge, Vivaldi, Brave).
    Chromium,
    /// Firefox and the Mozilla mail clients (Thunderbird, SeaMonkey).
    Firefox,
    /// Opera ≤ 12.
    OperaPresto,
    /// `index.dat` containers and the TypedURLs of `NTUSER.DAT`.
    InternetExplorer,
    /// URLs walked out of a damaged or carved SQLite file whose browser is unknown.
    Carved,
}

/// Chromium brands by a path fragment (lower case), first match wins. Data table: extend here.
const CHROMIUM_BRANDS: &[(&str, &str)] = &[
    ("yandex", "Yandex"),
    ("opera", "Opera"),
    ("microsoft/edge", "Edge"),
    ("microsoft-edge", "Edge"),
    ("vivaldi", "Vivaldi"),
    ("brave", "Brave"),
    ("chromium", "Chromium"),
    ("chrome", "Chrome"),
];

/// Mozilla products by a path fragment (lower case).
const MOZILLA_BRANDS: &[(&str, &str)] = &[("thunderbird", "Thunderbird"), ("seamonkey", "SeaMonkey")];

/// Folders whose next component is the user name.
const USER_ROOTS: &[&str] = &["documents and settings/", "users/", "home/"];

impl BrowserFamily {
    pub const ALL: [BrowserFamily; 5] = [Self::Chromium, Self::Firefox, Self::OperaPresto, Self::InternetExplorer, Self::Carved];

    /// The family of an event's parser, `None` when the parser is not a browser one.
    pub fn of(artifact: &str, kind: &str) -> Option<Self> {
        Some(match artifact {
            a if a.starts_with("chrome.") => Self::Chromium,
            a if a.starts_with("firefox.") => Self::Firefox,
            a if a.starts_with("opera.") => Self::OperaPresto,
            a if a.starts_with("ie.") => Self::InternetExplorer,
            "registry.ntuser" if kind == "UrlVisited" => Self::InternetExplorer,
            "sqlite.raw" => Self::Carved,
            _ => return None,
        })
    }

    /// The same test as [`Self::of`] as an SQL condition on `events` (no user input in it).
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::Chromium => "artifact LIKE 'chrome.%'",
            Self::Firefox => "artifact LIKE 'firefox.%'",
            Self::OperaPresto => "artifact LIKE 'opera.%'",
            Self::InternetExplorer => "(artifact LIKE 'ie.%' OR (artifact = 'registry.ntuser' AND kind = 'UrlVisited'))",
            Self::Carved => "artifact = 'sqlite.raw'",
        }
    }

    /// Any browser family, as one SQL condition.
    pub(crate) fn any_sql() -> String {
        format!("({})", Self::ALL.map(Self::sql).join(" OR "))
    }

    /// Product name, refined by the profile path where the family covers several browsers.
    pub fn browser_name(self, path_lower: &str) -> &'static str {
        let brand = |table: &[(&'static str, &'static str)], fallback| {
            table.iter().find(|(needle, _)| path_lower.contains(needle)).map_or(fallback, |(_, name)| *name)
        };
        match self {
            Self::Chromium => brand(CHROMIUM_BRANDS, "Chromium-based"),
            Self::Firefox => brand(MOZILLA_BRANDS, "Firefox"),
            Self::OperaPresto => "Opera (Presto)",
            Self::InternetExplorer => "Internet Explorer",
            Self::Carved => "Unknown (carved)",
        }
    }
}

/// One browser profile on one disk: the folder its databases live in. Internet Explorer keeps
/// its containers all over the user's folder, so the user folder is its profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ProfileKey {
    pub evidence: EvidenceId,
    pub family: BrowserFamily,
    /// Folder of the profile, `/`-separated as stored in `events.path`; empty when unknown.
    pub dir: String,
}

impl ProfileKey {
    /// Where an event of `artifact` read from `path` belongs.
    pub fn locate(evidence: EvidenceId, family: BrowserFamily, path: &str) -> Self {
        let parent = path.rsplit_once('/').map_or("", |(dir, _)| dir);
        let dir = match family {
            BrowserFamily::InternetExplorer => user_folder(path).unwrap_or(parent),
            _ => parent,
        };
        Self { evidence, family, dir: dir.to_string() }
    }

    /// `path` lies inside this profile's folder.
    pub fn contains(&self, path: &str) -> bool {
        self.dir.is_empty() || path.len() > self.dir.len() && path.starts_with(&self.dir) && path.as_bytes()[self.dir.len()] == b'/'
    }

    pub fn browser(&self) -> &'static str {
        self.family.browser_name(&self.dir.to_ascii_lowercase())
    }

    /// The OS user whose folder holds the profile.
    pub fn user(&self) -> Option<&str> {
        let lower = self.dir.to_ascii_lowercase();
        USER_ROOTS.iter().find_map(|root| {
            let at = lower.find(root).filter(|&i| i == 0 || lower.as_bytes()[i - 1] == b'/')? + root.len();
            let name = self.dir.get(at..)?.split('/').next()?;
            (!name.is_empty()).then_some(name)
        })
    }

    /// Short profile name: the folder name (`Default`, `abcd1234.default`), nothing for IE.
    pub fn name(&self) -> &str {
        match self.family {
            BrowserFamily::InternetExplorer => "",
            _ => self.dir.rsplit('/').next().unwrap_or(""),
        }
    }

    /// `Chrome · Admin / Default`, `Internet Explorer · Admin`.
    pub fn label(&self) -> String {
        let place = match (self.user(), self.name()) {
            (Some(u), "") => u.to_string(),
            (Some(u), n) => format!("{u} / {n}"),
            (None, "") => "(unknown folder)".to_string(),
            (None, n) => n.to_string(),
        };
        format!("{} · {place}", self.browser())
    }
}

/// `Documents and Settings/Admin` out of any path below it.
fn user_folder(path: &str) -> Option<&str> {
    let lower = path.to_ascii_lowercase();
    USER_ROOTS.iter().find_map(|root| {
        let start = lower.find(root).filter(|&i| i == 0 || lower.as_bytes()[i - 1] == b'/')? + root.len();
        let end = lower.get(start..)?.find('/').map_or(path.len(), |e| start + e);
        (end > start).then(|| path.get(..end)).flatten()
    })
}
