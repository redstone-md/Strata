//! Mail and IM artefacts: mbox / .eml headers, Outlook Express .dbx folders, IM account paths.
//! Containers and message decoding belong to the mail context ([`strata_mail`]).

mod dbx;
mod im;
mod rfc822;

pub(crate) use dbx::Dbx;
pub(crate) use im::ImPaths;

use crate::results::Recorder;
use rfc822::MailHeaders;
use strata_mail::Container;

const MAX_MESSAGES: usize = 100_000;

pub(crate) struct Mailbox;

impl Mailbox {
    /// An mbox (`From ` line) or an .eml (header block) by its first bytes.
    pub fn looks_like_mail(data: &[u8]) -> bool {
        matches!(Container::sniff(&data[..data.len().min(2048)]), Some(Container::Mbox | Container::Eml))
    }

    /// mbox (messages behind `From ` separator lines) or a single .eml.
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        if Container::sniff(data) != Some(Container::Mbox) {
            if let Some(h) = MailHeaders::parse(data) {
                h.record(rec, "eml");
            }
            return;
        }
        let (spans, _) = strata_mail::split_mbox(data, true);
        for span in spans.iter().take(MAX_MESSAGES) {
            let bytes = &data[span.offset as usize..(span.offset + span.len) as usize];
            if let Some(h) = MailHeaders::parse(bytes) {
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
        let mbox = b"From MAILER Sat May 14 17:36:09 2011\nFrom: a@example.ru\nSubject: one\nDate: Sat, 14 May 2011 17:36:09 +0000\n\nbody\n\
From MAILER Sun May 15 10:00:00 2011\nFrom: b@example.ru\nSubject: two\nDate: Sun, 15 May 2011 10:00:00 +0000\n\nbody\n";
        assert!(Mailbox::looks_like_mail(mbox));
        let mut rec = Recorder::new("mail.mbox");
        Mailbox::parse(mbox, &mut rec);
        assert_eq!(rec.finish().events.len(), 2);
        let eml = b"Subject: hi\r\nFrom: c@example.ru\r\nDate: Sat, 14 May 2011 17:36:09 +0000\r\n\r\nx";
        assert!(Mailbox::looks_like_mail(eml));
        let mut rec = Recorder::new("mail.eml");
        Mailbox::parse(eml, &mut rec);
        assert_eq!(rec.finish().events.len(), 1);
        assert!(!Mailbox::looks_like_mail(b"\x00\x01garbage"));
    }
}
