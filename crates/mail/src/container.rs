//! What holds a message: one `.eml` file, an mbox, an Outlook Express folder, or nothing
//! (carved from free space). Recognised by name and by content.

use crate::dbx::Dbx;
use crate::lines::{HeaderBlock, is_separator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Container {
    /// One message per file (`.eml`, `.nws`; Windows Live Mail, Outlook Express exports).
    Eml,
    /// Messages behind `From ` lines (Thunderbird, Linux spools, Opera `.mbs`).
    Mbox,
    /// Outlook Express folder.
    Dbx,
    /// Found in free space, outside any file.
    Carved,
}

impl Container {
    pub fn name(self) -> &'static str {
        match self {
            Self::Eml => "eml",
            Self::Mbox => "mbox",
            Self::Dbx => "dbx",
            Self::Carved => "carved",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::Eml, Self::Mbox, Self::Dbx, Self::Carved].into_iter().find(|c| c.name() == name)
    }

    /// Mail container by file path alone: extension, or a Thunderbird mail folder file.
    pub fn by_name(path: &str) -> Option<Self> {
        let lower = path.replace('\\', "/").to_ascii_lowercase();
        let name = lower.rsplit('/').next().unwrap_or_default();
        let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
        let under = |p: &str| lower.contains(p) || lower.starts_with(&p[1..]);
        match ext {
            "dbx" => Some(Self::Dbx),
            "eml" | "nws" => Some(Self::Eml),
            "mbox" | "mbx" | "mbs" => Some(Self::Mbox),
            "" if (under("/thunderbird/profiles/") || under("/.thunderbird/")) && (under("/mail/") || under("/imapmail/")) => Some(Self::Mbox),
            _ => None,
        }
    }

    /// Mail container by the first bytes of a file.
    pub fn sniff(head: &[u8]) -> Option<Self> {
        if Dbx::is_dbx(head) {
            Some(Self::Dbx)
        } else if is_separator(head, 0) {
            Some(Self::Mbox)
        } else if HeaderBlock::at(head, 0).is_message() {
            Some(Self::Eml)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_and_by_content() {
        assert_eq!(Container::by_name(r"Users\a\Local Settings\Outlook Express\Inbox.dbx"), Some(Container::Dbx));
        assert_eq!(Container::by_name("Users/a/AppData/Roaming/Thunderbird/Profiles/x.default/Mail/Local Folders/Inbox"), Some(Container::Mbox));
        assert_eq!(Container::by_name("home/a/.thunderbird/x.default/ImapMail/imap.example.com/INBOX"), Some(Container::Mbox));
        assert_eq!(Container::by_name("Users/a/Mail/msg.EML"), Some(Container::Eml));
        assert_eq!(Container::by_name("Users/a/Inbox.msf"), None);
        assert_eq!(Container::sniff(b"From x Mon\nSubject: a\n"), Some(Container::Mbox));
        assert_eq!(Container::sniff(b"Subject: a\r\nFrom: b@example.com\r\n\r\n"), Some(Container::Eml));
        assert_eq!(Container::sniff(&crate::dbx::DBX_MAGIC), Some(Container::Dbx));
        assert_eq!(Container::sniff(b"\x00garbage"), None);
        assert_eq!(Container::parse("dbx"), Some(Container::Dbx));
    }
}
