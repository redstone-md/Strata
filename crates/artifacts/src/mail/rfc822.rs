//! Timeline events and identities from message headers (mbox, .eml, Outlook Express message
//! bodies). Decoding is the mail context's ([`strata_mail::Envelope`]).

use crate::results::{IdentityKind, Recorder};
use crate::text::is_email;
use strata_accounts::{Catalogue, Service, ServiceKind};
use strata_mail::{Envelope, Party, join};
use strata_timeline::EventKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailHeaders {
    envelope: Envelope,
}

impl MailHeaders {
    /// The header block at the start of `raw`, when it names a sender or a subject.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        Envelope::parse(raw).filter(|e| !e.from.is_empty() || !e.subject.is_empty()).map(|envelope| Self { envelope })
    }

    pub fn record(&self, rec: &mut Recorder, label: &str) {
        let e = &self.envelope;
        let at = e.date;
        let title = if e.subject.is_empty() { "(no subject)".to_string() } else { e.subject.clone() };
        let sender = self.service_sender();
        let mut event =
            rec.make(at, EventKind::Email, title.clone()).map(|ev| ev.with_detail(format!("{label}: from {} to {}", join(&e.from), join(&e.to))));
        if let (Some(ev), Some(_)) = (event.as_mut(), sender)
            && Catalogue::shared().is_money_subject(&e.subject)
        {
            ev.add_tag("money");
        }
        match event {
            Some(ev) => rec.push(ev),
            None => rec.emit(None, EventKind::Email, title, ""),
        }
        for field in [&e.from, &e.to, &e.cc] {
            for addr in addresses(field) {
                rec.identity(IdentityKind::Email, &addr, None, at);
            }
        }
        // Mail from a catalogued service to an address: that address has an account there; a
        // welcome / confirmation subject dates when it was opened.
        if let Some(service) = sender {
            let signup = Catalogue::shared().is_signup_subject(&e.subject);
            for addr in addresses(&e.to) {
                let note = format!("mail from {}: {}", service.name, e.subject);
                rec.identity_noted(IdentityKind::Email, &addr, Some(service.name), at, &note);
                if signup {
                    rec.dated(at, EventKind::AccountSeen, format!("{} account {addr}", service.name), format!("registration mail: {}", e.subject));
                }
            }
        }
    }

    /// The service that sent the message, when it is catalogued and not a plain mailbox.
    fn service_sender(&self) -> Option<Service> {
        addresses(&self.envelope.from)
            .first()
            .and_then(|a| Service::classify_email(a))
            .filter(|s| !matches!(s.kind, ServiceKind::Mail | ServiceKind::Other))
    }
}

/// Plausible e-mail addresses of an address header.
fn addresses(parties: &[Party]) -> Vec<String> {
    parties.iter().map(|p| p.address.trim_end_matches('.').to_string()).filter(|a| is_email(a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_encoded_words() {
        let msg = "From: \"Svetla\" <anna.test3@example.ru>\r\nTo: ivan.test2@example.ru,\r\n olga.test1@example.ru\r\n\
                   Subject: =?utf-8?B?0LHQuNGC0LrQvtC40L0=?=\r\nDate: Tue, 31 Jan 2012 23:57:06 +0400\r\n\r\nbody From: x";
        let h = MailHeaders::parse(msg.as_bytes()).unwrap();
        assert_eq!(h.envelope.subject, "биткоин");
        assert_eq!(addresses(&h.envelope.to), vec!["ivan.test2@example.ru", "olga.test1@example.ru"]);
        let mut rec = Recorder::new("mail");
        h.record(&mut rec, "mbox");
        let out = rec.finish();
        assert_eq!(out.events[0].at().to_string(), "2012-01-31 19:57:06");
        assert_eq!(out.identities.len(), 3);
        assert!(MailHeaders::parse(b"garbage").is_none());
    }

    #[test]
    fn service_mail_names_the_account() {
        let msg = "From: Mt.Gox <noreply@mtgox.com>\r\nTo: gox.tester@example.ru\r\nSubject: Welcome to Mt.Gox\r\n\
                   Date: Tue, 14 Jun 2011 10:00:00 +0000\r\n\r\nbody";
        let mut rec = Recorder::new("mail");
        MailHeaders::parse(msg.as_bytes()).unwrap().record(&mut rec, "eml");
        let out = rec.finish();
        let gox = out.identities.iter().find(|i| i.service.as_deref() == Some("Mt. Gox")).unwrap();
        assert_eq!(gox.value, "gox.tester@example.ru");
        assert!(out.events.iter().any(|e| e.kind() == EventKind::AccountSeen && e.title().contains("gox.tester@example.ru")));
        let money = "From: support@btc-e.com\r\nTo: a.test@example.ru\r\nSubject: Withdrawal confirmed\r\nDate: Tue, 14 Jun 2011 10:00:00 +0000\r\n\r\n";
        let mut rec = Recorder::new("mail");
        MailHeaders::parse(money.as_bytes()).unwrap().record(&mut rec, "eml");
        assert!(rec.finish().events[0].has_tag("money"));
    }
}
