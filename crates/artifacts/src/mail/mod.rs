//! Mail and IM artefacts: mbox / .eml headers, Outlook Express .dbx folders, IM account paths.

mod dbx;
mod im;
mod rfc822;

pub(crate) use dbx::Dbx;
pub(crate) use im::{ImAccount, ImPaths};

use crate::results::Recorder;
use rfc822::MailHeaders;

const MAX_MESSAGES: usize = 100_000;

pub(crate) struct Mailbox;

impl Mailbox {
    /// Heuristic: an mbox starts with `From ` and an .eml with a header line.
    pub fn looks_like_mail(data: &[u8]) -> bool {
        let head = String::from_utf8_lossy(&data[..data.len().min(2048)]);
        head.starts_with("From ") || MailHeaders::parse(&head).is_some()
    }

    /// mbox (messages separated by `\nFrom ` lines, each starting with the separator line) or
    /// a single .eml.
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = String::from_utf8_lossy(data);
        if !text.starts_with("From ") {
            if let Some(h) = MailHeaders::parse(&text) {
                h.record(rec, "eml");
            }
            return;
        }
        for msg in text.split("\nFrom ").take(MAX_MESSAGES) {
            let body = msg.split_once('\n').map_or("", |(_, rest)| rest);
            if let Some(h) = MailHeaders::parse(body) {
                h.record(rec, "mbox");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbox_and_eml() {
        let mbox = b"From MAILER Sat May 14 17:36:09 2011\nFrom: a@mail.ru\nSubject: one\nDate: Sat, 14 May 2011 17:36:09 +0000\n\nbody\n\
From MAILER Sun May 15 10:00:00 2011\nFrom: b@mail.ru\nSubject: two\nDate: Sun, 15 May 2011 10:00:00 +0000\n\nbody\n";
        assert!(Mailbox::looks_like_mail(mbox));
        let mut rec = Recorder::new("mail.mbox");
        Mailbox::parse(mbox, &mut rec);
        assert_eq!(rec.finish().events.len(), 2);
        let eml = b"Subject: hi\r\nFrom: c@mail.ru\r\nDate: Sat, 14 May 2011 17:36:09 +0000\r\n\r\nx";
        assert!(Mailbox::looks_like_mail(eml));
        let mut rec = Recorder::new("mail.eml");
        Mailbox::parse(eml, &mut rec);
        assert_eq!(rec.finish().events.len(), 1);
        assert!(!Mailbox::looks_like_mail(b"\x00\x01garbage"));
    }
}
