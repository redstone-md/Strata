use super::config_text;
use crate::results::{IdentityKind, Recorder};
use crate::text::is_email;

/// Windows Live Mail / Windows Mail `*.oeaccount` (XML, usually UTF-16).
pub(crate) struct OeAccount;

/// `(login tag, server tag)` pairs per protocol.
const LOGINS: &[(&str, &str)] = &[
    ("POP3_User_Name", "POP3_Server"),
    ("IMAP_User_Name", "IMAP_Server"),
    ("HTTPMail_User_Name", "HTTPMail_Server"),
    ("SMTP_User_Name", "SMTP_Server"),
];

/// Text of `<tag ...>value</tag>`.
fn tag_value(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = text.find(&open)?;
    let after = text.get(start + open.len()..)?;
    let body = after.get(after.find('>')? + 1..)?;
    let value = body.get(..body.find(&format!("</{tag}>"))?)?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

impl OeAccount {
    pub fn looks_like(text: &str) -> bool {
        text.contains("<MessageAccount")
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = config_text(data);
        if let Some(name) = tag_value(&text, "Account_Name") {
            rec.fact("mail_account", name);
        }
        if let Some(addr) = tag_value(&text, "SMTP_Email_Address").filter(|a| is_email(a)) {
            rec.identity_noted(IdentityKind::Email, &addr, None, None, "Windows Live Mail account");
        }
        for (login, server) in LOGINS {
            let Some(user) = tag_value(&text, login) else { continue };
            let host = tag_value(&text, server);
            let kind = if is_email(&user) { IdentityKind::Email } else { IdentityKind::Login };
            rec.identity_noted(kind, &user, host.as_deref(), None, &format!("Windows Live Mail {login}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_mail_account() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><MessageAccount><Account_Name type=\"SZ\">mail.ru</Account_Name>\
                   <POP3_Server type=\"SZ\">pop.mail.ru</POP3_Server><POP3_User_Name type=\"SZ\">ivan.test2</POP3_User_Name>\
                   <SMTP_Email_Address type=\"SZ\">ivan.test2@mail.ru</SMTP_Email_Address></MessageAccount>";
        let wide: Vec<u8> = [0xFF, 0xFE].into_iter().chain(xml.bytes().flat_map(|b| [b, 0])).collect();
        assert!(OeAccount::looks_like(&config_text(&wide)));
        let mut rec = Recorder::new("mail.oeaccount");
        OeAccount::parse(&wide, &mut rec);
        let out = rec.finish();
        let ids: Vec<_> = out.identities.iter().map(|i| (i.value.as_str(), i.service.as_deref())).collect();
        assert_eq!(ids, [("ivan.test2@mail.ru", None), ("ivan.test2", Some("pop.mail.ru"))]);
        assert_eq!(out.facts[0].value, "mail.ru");
    }
}
