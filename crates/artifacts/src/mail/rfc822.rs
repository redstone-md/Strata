//! RFC 822 message headers (mbox, .eml, Outlook Express message bodies), with RFC 2047
//! encoded-word decoding for UTF-8 / Windows-1251 (the common Russian webmail encodings).

use crate::results::{IdentityKind, Recorder};
use crate::text::{ansi, is_email, parse_rfc2822};
use strata_timeline::EventKind;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct MailHeaders {
    pub from: String,
    pub to: String,
    pub cc: String,
    pub subject: String,
    pub date: String,
}

impl MailHeaders {
    /// Parse the header block at the start of `text` (stops at the first blank line).
    pub fn parse(text: &str) -> Option<Self> {
        let mut h = MailHeaders::default();
        let mut current: Option<(String, String)> = None;
        let mut seen = 0;
        let mut commit = |cur: Option<(String, String)>, h: &mut MailHeaders| {
            if let Some((name, value)) = cur {
                let value = decode_words(value.trim());
                let slot = match name.to_ascii_lowercase().as_str() {
                    "from" => &mut h.from,
                    "to" => &mut h.to,
                    "cc" => &mut h.cc,
                    "subject" => &mut h.subject,
                    "date" => &mut h.date,
                    _ => return 0,
                };
                if slot.is_empty() {
                    *slot = value;
                }
                return 1;
            }
            0
        };
        for line in text.lines().take(400) {
            if line.trim().is_empty() {
                break;
            }
            if line.starts_with([' ', '\t']) {
                if let Some((_, v)) = current.as_mut() {
                    v.push(' ');
                    v.push_str(line.trim());
                }
                continue;
            }
            seen += commit(current.take(), &mut h);
            current = line.split_once(':').map(|(n, v)| (n.trim().to_string(), v.to_string()));
        }
        seen += commit(current.take(), &mut h);
        (seen >= 2 && (!h.from.is_empty() || !h.subject.is_empty())).then_some(h)
    }

    pub fn record(&self, rec: &mut Recorder, label: &str) {
        let at = parse_rfc2822(&self.date);
        let title = if self.subject.is_empty() { "(no subject)".to_string() } else { self.subject.clone() };
        rec.emit(at, EventKind::Email, title, format!("{label}: from {} to {}", self.from, self.to));
        for field in [&self.from, &self.to, &self.cc] {
            for addr in addresses(field) {
                rec.identity(IdentityKind::Email, &addr, None, at);
            }
        }
    }
}

/// E-mail addresses in an address-list header.
pub(crate) fn addresses(field: &str) -> Vec<String> {
    field
        .split([',', ';', ' ', '<', '>', '"', '\'', '(', ')'])
        .map(|t| t.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|t| is_email(t))
        .collect()
}

/// `=?charset?B|Q?text?=` → text; unknown charsets are left encoded.
fn decode_words(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        let Some(word) = encoded_word(&rest[start..]) else {
            out.push_str(&rest[..start + 2]);
            rest = &rest[start + 2..];
            continue;
        };
        let before = &rest[..start];
        if !(before.trim().is_empty() && !out.is_empty()) {
            out.push_str(before);
        }
        out.push_str(&word.0);
        rest = &rest[start + word.1..];
    }
    out.push_str(rest);
    out
}

/// Decode one encoded word at the start of `s`; returns (text, consumed bytes).
fn encoded_word(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix("=?")?;
    let (charset, body) = body.split_once('?')?;
    let (enc, body) = body.split_once('?')?;
    let end = body.find("?=")?;
    let payload = &body[..end];
    let bytes = match enc {
        "B" | "b" => base64(payload)?,
        "Q" | "q" => quoted(payload),
        _ => return None,
    };
    let text = match charset.to_ascii_lowercase().as_str() {
        "utf-8" | "us-ascii" => String::from_utf8_lossy(&bytes).into_owned(),
        "windows-1251" | "cp1251" => ansi(&bytes),
        _ => return None,
    };
    Some((text, 2 + charset.len() + 1 + enc.len() + 1 + end + 2))
}

fn quoted(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'_' => out.push(b' '),
            b'=' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'='),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=' && !c.is_ascii_whitespace()) {
        acc = (acc << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_encoded_words() {
        let msg = "From: \"Svetla\" <anna.test3@mail.ru>\r\nTo: ivan.test2@mail.ru,\r\n olga.test1@mail.ru\r\n\
                   Subject: =?utf-8?B?0LHQuNGC0LrQvtC40L0=?=\r\nDate: Tue, 31 Jan 2012 23:57:06 +0400\r\n\r\nbody From: x";
        let h = MailHeaders::parse(msg).unwrap();
        assert_eq!(h.subject, "биткоин");
        assert_eq!(addresses(&h.to), vec!["ivan.test2@mail.ru", "olga.test1@mail.ru"]);
        let mut rec = Recorder::new("mail");
        h.record(&mut rec, "mbox");
        let out = rec.finish();
        assert_eq!(out.events[0].at().to_string(), "2012-01-31 19:57:06");
        assert_eq!(out.identities.len(), 3);
        assert_eq!(decode_words("=?windows-1251?Q?=CF=F0=E8_x?="), "При x");
        assert_eq!(decode_words("a =?bad"), "a =?bad");
        assert!(MailHeaders::parse("garbage").is_none());
        let _ = quoted("=");
        let _ = quoted("=4");
    }
}
