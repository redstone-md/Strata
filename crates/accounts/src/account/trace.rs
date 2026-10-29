//! How strongly one trace says the account was the owner's: a saved password or a mail client
//! set up for the address is use; the same address in a cached page or in a stranger's mail
//! header is only a sighting.

use serde::{Deserialize, Serialize};

/// What kind of trace names an account, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TraceKind {
    /// A browser saved the login (and its password).
    SavedPassword,
    /// A mail client was set up for the account (registry, prefs.js, .oeaccount).
    MailAccount,
    /// A Windows user (SAM, profile list, logon events).
    SystemUser,
    /// The address receives most of the mail in a mailbox found on the disk.
    MailboxOwner,
    /// The address sent mail kept in a Sent folder.
    SentMail,
    /// A program's settings name the account (mining pool login, Firefox Sync).
    AppConfig,
    /// A messenger or program keeps a folder or registry key for the account.
    ProfileFolder,
    /// The user typed the value into a form (form history, autofill profile).
    Autofill,
    /// A catalogued service mailed the address (registration, notices).
    ServiceMail,
    /// The address was used as the login of another service.
    UsedElsewhere,
    /// A site kept the login in a cookie.
    Cookie,
    /// A visited URL carried the login (`?login=`).
    VisitedLogin,
    /// A login or account event mentions the identifier.
    AccountEvent,
    /// The address is in the From/To/Cc of a stored message.
    Correspondent,
    /// Somebody's profile page was visited.
    ProfileVisit,
    /// A URL with the login was found somewhere in the bytes of the disk.
    UrlMention,
    /// The value merely appears in a file or in free space.
    #[default]
    Mention,
}

impl TraceKind {
    /// 0..1: how likely this one trace alone means the owner used the account.
    pub fn weight(self) -> f32 {
        match self {
            Self::SavedPassword => 0.95,
            Self::MailAccount | Self::SystemUser => 0.9,
            Self::MailboxOwner | Self::SentMail => 0.85,
            Self::AppConfig | Self::ProfileFolder => 0.8,
            Self::Autofill => 0.7,
            Self::ServiceMail => 0.65,
            Self::UsedElsewhere => 0.6,
            Self::Cookie | Self::VisitedLogin | Self::AccountEvent => 0.55,
            Self::Correspondent => 0.25,
            Self::ProfileVisit | Self::UrlMention => 0.2,
            Self::Mention => 0.1,
        }
    }

    /// The trace shows the account in use on this machine (not just its name in some data).
    pub fn is_use(self) -> bool {
        self.weight() >= 0.5
    }

    /// The trace carries a secret (a saved password) besides the name.
    pub fn has_secret(self) -> bool {
        self == Self::SavedPassword
    }

    /// Short reason as the UI lists it ("why this is the owner's account").
    pub fn label(self) -> &'static str {
        match self {
            Self::SavedPassword => "saved password",
            Self::MailAccount => "mail client account",
            Self::SystemUser => "Windows user",
            Self::MailboxOwner => "owner of a mailbox",
            Self::SentMail => "sent mail",
            Self::AppConfig => "program settings",
            Self::ProfileFolder => "profile folder",
            Self::Autofill => "typed into a form",
            Self::ServiceMail => "mail from the service",
            Self::UsedElsewhere => "used as a login elsewhere",
            Self::Cookie => "login cookie",
            Self::VisitedLogin => "login in a visited URL",
            Self::AccountEvent => "login or account event",
            Self::Correspondent => "in mail headers",
            Self::ProfileVisit => "profile page visited",
            Self::UrlMention => "in a URL on the disk",
            Self::Mention => "found in data",
        }
    }

    /// The trace a mailbox gets when its address is the login of another account.
    pub fn for_mailbox(self) -> Self {
        if self.is_use() { Self::UsedElsewhere } else { self }
    }

    /// Classify an identity an artefact parser recorded, from its note, service and file.
    /// Older cases have no notes for some parsers; the file then tells.
    pub fn of_artefact(detail: &str, service: Option<&str>, source: &str, weak: bool) -> Self {
        let d = detail.to_lowercase();
        let has = |w: &str| d.contains(w);
        if weak || d.starts_with("profile page") {
            Self::ProfileVisit
        } else if d.starts_with("mail from ") {
            Self::ServiceMail
        } else if has("saved browser login") || has("saved password") {
            Self::SavedPassword
        } else if d.starts_with("mail sender") || d.starts_with("mail recipient") {
            Self::Correspondent
        } else if d.starts_with("cookie") {
            Self::Cookie
        } else if d.starts_with("form history") || d.starts_with("autofill") {
            Self::Autofill
        } else if d.starts_with("url field") {
            Self::VisitedLogin
        } else if has("mail identity") || has("mail server") || has("mail account") || has("windows live mail") {
            Self::MailAccount
        } else if !d.is_empty() {
            Self::AppConfig
        } else {
            Self::of_unnoted(service, source)
        }
    }

    fn of_unnoted(service: Option<&str>, source: &str) -> Self {
        let path = source.replace('\\', "/").to_lowercase();
        let file = path.rsplit('/').next().unwrap_or_default();
        match service {
            Some(s) if s.eq_ignore_ascii_case("windows") => Self::SystemUser,
            Some(s) if file == "ntuser.dat" && !s.eq_ignore_ascii_case("icq") => Self::MailAccount,
            _ if file == "web data" => Self::Autofill,
            None if looks_like_mail_store(&path) => Self::Correspondent,
            Some(_) => Self::ProfileFolder,
            None => Self::Mention,
        }
    }
}

/// A mailbox or message file (mbox, Outlook Express, Thunderbird, .eml).
fn looks_like_mail_store(path: &str) -> bool {
    const EXTENSIONS: &[&str] = &[".mbox", ".mbx", ".dbx", ".eml", ".msg", ".pst", ".ost", ".msf"];
    const FOLDERS: &[&str] = &["imapmail/", "/mail/", "outlook express/", "windows mail/", "windows live mail/", "thunderbird/"];
    const NAMES: &[&str] = &["inbox", "sent", "drafts", "trash", "входящие", "отправленные"];
    let file = path.rsplit('/').next().unwrap_or_default();
    EXTENSIONS.iter().any(|e| file.ends_with(e)) || FOLDERS.iter().any(|f| path.contains(f)) || NAMES.contains(&file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_decide_first() {
        assert_eq!(TraceKind::of_artefact("saved browser login", None, "x/Login Data", false), TraceKind::SavedPassword);
        assert_eq!(TraceKind::of_artefact("cookie remember_user", Some("forum.example.com"), "x/Cookies", false), TraceKind::Cookie);
        assert_eq!(TraceKind::of_artefact("form history field email", None, "x/formhistory.sqlite", false), TraceKind::Autofill);
        assert_eq!(TraceKind::of_artefact("URL field login=", Some("Mt. Gox"), "x/History", false), TraceKind::VisitedLogin);
        assert_eq!(TraceKind::of_artefact("URL field login=", Some("Mt. Gox"), "x/History", true), TraceKind::ProfileVisit);
        assert_eq!(TraceKind::of_artefact("mail server login on pop.example.com (prefs.js)", None, "p/prefs.js", false), TraceKind::MailAccount);
        assert_eq!(TraceKind::of_artefact("mail from Mt. Gox: password reset", Some("Mt. Gox"), "m/INBOX", false), TraceKind::ServiceMail);
        assert_eq!(TraceKind::of_artefact("autofill field email", None, "x/Web Data", false), TraceKind::Autofill);
        assert_eq!(TraceKind::of_artefact("mining pool login (worker a.1)", Some("Slush Pool"), "cgminer.conf", false), TraceKind::AppConfig);
        assert_eq!(TraceKind::of_artefact("mail recipient", None, "m/INBOX", false), TraceKind::Correspondent);
    }

    #[test]
    fn unnoted_traces_go_by_service_and_file() {
        assert_eq!(TraceKind::of_artefact("", Some("Windows"), "WINDOWS/system32/config/SAM", false), TraceKind::SystemUser);
        assert_eq!(TraceKind::of_artefact("", Some("pop.example.com"), "Documents and Settings/a/NTUSER.DAT", false), TraceKind::MailAccount);
        assert_eq!(TraceKind::of_artefact("", Some("ICQ"), "Documents and Settings/a/NTUSER.DAT", false), TraceKind::ProfileFolder);
        assert_eq!(TraceKind::of_artefact("", None, "a/Google/Chrome/User Data/Default/Web Data", false), TraceKind::Autofill);
        assert_eq!(TraceKind::of_artefact("", None, "home/a/.thunderbird/x.default/ImapMail/mail.example.com/INBOX", false), TraceKind::Correspondent);
        assert_eq!(TraceKind::of_artefact("", None, "Identities/{1}/Microsoft/Outlook Express/Inbox.dbx", false), TraceKind::Correspondent);
        assert_eq!(TraceKind::of_artefact("", Some("Skype"), "a/Application Data/Skype/test_user/config.xml", false), TraceKind::ProfileFolder);
        assert_eq!(TraceKind::of_artefact("", None, "a/notes.txt", false), TraceKind::Mention);
    }

    #[test]
    fn use_and_sightings() {
        assert!(TraceKind::SavedPassword.is_use() && TraceKind::SavedPassword.has_secret());
        assert!(TraceKind::Cookie.is_use() && !TraceKind::Cookie.has_secret());
        assert!(!TraceKind::Correspondent.is_use() && !TraceKind::Mention.is_use() && !TraceKind::ProfileVisit.is_use());
        assert_eq!(TraceKind::SavedPassword.for_mailbox(), TraceKind::UsedElsewhere);
        assert_eq!(TraceKind::UrlMention.for_mailbox(), TraceKind::UrlMention);
        assert!(TraceKind::SavedPassword < TraceKind::Mention, "declared strongest first");
    }
}
