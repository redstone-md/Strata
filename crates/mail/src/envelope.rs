//! Who wrote to whom, when and about what: the summary headers of a message, decoded
//! (RFC 2047 words, any charset `mail-parser` knows).

use mail_parser::{AddressList, MessageParser, MessageRef};
use serde::{Deserialize, Serialize};
use std::fmt;
use strata_kernel::Timestamp;

/// One mailbox of an address header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    pub name: Option<String>,
    /// Lowercased; empty when the header named nobody parseable.
    pub address: String,
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.name, self.address.is_empty()) {
            (Some(n), false) => write!(f, "{n} <{}>", self.address),
            (Some(n), true) => f.write_str(n),
            (None, _) => f.write_str(&self.address),
        }
    }
}

/// `a, Name <b>` for a list of parties.
pub fn join(parties: &[Party]) -> String {
    parties.iter().map(Party::to_string).collect::<Vec<_>>().join(", ")
}

/// Summary headers of one message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Without angle brackets.
    pub message_id: Option<String>,
    pub date: Option<Timestamp>,
    pub from: Vec<Party>,
    pub to: Vec<Party>,
    pub cc: Vec<Party>,
    pub subject: String,
}

impl Envelope {
    /// The header block at the start of `raw`, when it names a sender, a subject, recipients,
    /// a date or a message id. Only headers are parsed.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let parsed = MessageParser::new().parse_headers(raw)?;
        Some(Self::of(parsed.root())).filter(|e| !e.is_empty())
    }

    pub(crate) fn of(m: MessageRef<'_>) -> Self {
        let parties = |list: Option<AddressList<'_>>| -> Vec<Party> {
            list.map(|l| {
                l.mailboxes()
                    .map(|m| Party {
                        name: m.name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string),
                        address: m.address().unwrap_or_default().trim().to_ascii_lowercase(),
                    })
                    .filter(|p| p.name.is_some() || !p.address.is_empty())
                    .collect()
            })
            .unwrap_or_default()
        };
        Self {
            message_id: m.message_id().map(|id| id.trim().to_string()).filter(|id| !id.is_empty()),
            date: m.date().filter(|d| d.is_valid()).and_then(|d| Timestamp::from_unix_secs(d.to_timestamp())),
            from: parties(m.from()),
            to: parties(m.to()),
            cc: parties(m.cc()),
            subject: m.subject().unwrap_or_default().trim().to_string(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.message_id.is_none() && self.date.is_none() && self.from.is_empty() && self.to.is_empty() && self.subject.is_empty()
    }

    /// Every distinct address in From, To and Cc, lowercased.
    pub fn addresses(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for p in self.from.iter().chain(&self.to).chain(&self.cc) {
            if p.address.contains('@') && !out.contains(&p.address) {
                out.push(p.address.clone());
            }
        }
        out
    }

    /// Same message wherever it is found: Message-ID and date, or (without an id) a hash of
    /// sender, recipients, date and subject.
    pub fn fingerprint(&self) -> String {
        let date = self.date.map_or(0, |d| d.unix_secs());
        match &self.message_id {
            Some(id) => format!("id:{}|{date}", id.to_ascii_lowercase()),
            None => {
                let key = format!("{}|{}|{date}|{}", join(&self.from), join(&self.to), self.subject);
                format!("h:{:016x}", fnv1a(key.as_bytes()))
            }
        }
    }
}

/// FNV-1a 64: a stable hash for fingerprints (std's hasher may change between releases).
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_summary_headers() {
        let raw = "From: \"Anna\" <Anna@Example.com>\r\nTo: ivan@example.com,\r\n olga@example.ru\r\n\
                   Subject: =?utf-8?B?0LHQuNGC0LrQvtC40L0=?=\r\nDate: Tue, 31 Jan 2012 23:57:06 +0400\r\n\
                   Message-ID: <abc@example.com>\r\n\r\nbody";
        let e = Envelope::parse(raw.as_bytes()).unwrap();
        assert_eq!(e.subject, "биткоин");
        assert_eq!(e.from[0].to_string(), "Anna <anna@example.com>");
        assert_eq!(e.addresses(), vec!["anna@example.com", "ivan@example.com", "olga@example.ru"]);
        assert_eq!(e.date.unwrap().to_string(), "2012-01-31 19:57:06");
        assert_eq!(e.message_id.as_deref(), Some("abc@example.com"));
        assert!(e.fingerprint().starts_with("id:abc@example.com|"));
        let cp1251 = Envelope::parse(b"Subject: =?windows-1251?Q?=CF=F0=E8_x?=\r\nFrom: a@example.com\r\n\r\n").unwrap();
        assert_eq!(cp1251.subject, "При x");
        assert!(cp1251.fingerprint().starts_with("h:"));
        assert!(Envelope::parse(b"").is_none());
        assert_eq!(join(&[Party { name: Some("x".into()), address: String::new() }]), "x");
    }
}
