//! Instant-messenger and webmail-agent traces recognised from file paths alone: Mail.ru Agent,
//! ICQ, QIP history folders and IE DOMStore `…mailru.webagent.mail[1].xml` files.

use crate::results::IdentityKind;
use crate::text::is_email;

/// An account implied by where a file lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImAccount {
    pub kind: IdentityKind,
    pub value: String,
    pub service: &'static str,
}

/// Mail.ru-family domains as they appear squashed in WebAgent DOMStore file names.
const WEBAGENT_DOMAINS: &[(&str, &str)] = &[("mailru", "mail.ru"), ("bkru", "bk.ru"), ("inboxru", "inbox.ru"), ("listru", "list.ru")];

pub(crate) struct ImPaths;

impl ImPaths {
    /// Accounts implied by `path` (`/`-separated, any case).
    pub fn accounts(path: &str) -> Vec<ImAccount> {
        let lower = path.to_lowercase();
        let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
        let lparts: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
        let mut out = Vec::new();
        let mut push = |kind, value: &str, service| {
            let a = ImAccount { kind, value: value.to_string(), service };
            if !out.contains(&a) {
                out.push(a);
            }
        };
        if lower.contains("mail.ru/agent") || lower.contains("/mra/") || lower.contains("magent") {
            for p in parts.iter().filter(|p| is_email(p)) {
                push(IdentityKind::Email, p, "Mail.ru Agent");
            }
        }
        for (i, p) in lparts.iter().enumerate() {
            let next = parts.get(i + 1).copied().unwrap_or("");
            let after = parts.get(i + 2).copied().unwrap_or("");
            if (p == "icq" || p.starts_with("icq ") || p == "icqlite") && is_uin(next) {
                push(IdentityKind::Nickname, next, "ICQ");
            }
            if p == "skype" && SKYPE_PROFILE_FILES.contains(&lparts.get(i + 2).map(String::as_str).unwrap_or("")) && is_skype_name(next) {
                push(IdentityKind::Login, next, "Skype");
            }
            if (p == "miranda im" || p == "miranda" || p == "miranda ng")
                && lparts.get(i + 1).is_some_and(|n| n == "profiles")
                && let Some(stem) = after.strip_suffix(".dat").filter(|s| !s.is_empty())
            {
                push(IdentityKind::Nickname, stem, "Miranda IM");
            }
            if p.starts_with("qip") && (lparts.get(i + 1).is_some_and(|n| n == "users" || n == "profiles")) && (is_uin(after) || is_email(after)) {
                let kind = if is_email(after) { IdentityKind::Email } else { IdentityKind::Nickname };
                push(kind, after, "QIP");
            }
        }
        if let Some(name) = parts.last()
            && let Some(email) = webagent_email(name)
        {
            push(IdentityKind::Email, &email, "Mail.ru Agent (web)");
        }
        out
    }
}

/// `olga.test1mailru.webagent.mail[1].xml` → `olga.test1@mail.ru`.
fn webagent_email(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.split(".webagent.").next().filter(|s| s.len() < lower.len())?;
    WEBAGENT_DOMAINS.iter().find_map(|(squashed, domain)| {
        let user = stem.strip_suffix(squashed)?;
        (!user.is_empty()).then(|| format!("{user}@{domain}"))
    })
}

/// Files directly inside a Skype account folder (`Skype/<skypename>/main.db`).
const SKYPE_PROFILE_FILES: &[&str] = &["main.db", "config.xml", "chatsync", "voicemail", "httpfe", "media_messaging", "keyval.db"];

/// Skype names: 6–32 characters, starting with a letter (`live:` names are also accounts).
fn is_skype_name(s: &str) -> bool {
    let name = s.strip_prefix("live#3a").unwrap_or(s);
    (6..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b".,_-".contains(&b))
}

fn is_uin(s: &str) -> bool {
    (5..=10).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_accounts() {
        let v = |p: &str| ImPaths::accounts(p).into_iter().map(|a| (a.value, a.service)).collect::<Vec<_>>();
        assert_eq!(
            v("Documents and Settings/Admin/Local Settings/Application Data/Microsoft/Internet Explorer/DOMStore/POFAU5IQ/olga.test1mailru.webagent.mail[1].xml"),
            vec![("olga.test1@mail.ru".to_string(), "Mail.ru Agent (web)")]
        );
        assert_eq!(v("Users/a/AppData/Roaming/Mail.Ru/Agent/magent_logs/ivan.test2@mail.ru/log.txt")[0].0, "ivan.test2@mail.ru");
        assert_eq!(v("Program Files/QIP/Users/123456789/History/555555.qhf")[0].0, "123456789");
        assert_eq!(v("Documents and Settings/a/Application Data/ICQ/987654/Messages.mdb")[0].1, "ICQ");
        assert!(v("Windows/System32/icq/x").is_empty());
        assert_eq!(v("Users/a/AppData/Roaming/Skype/skype.tester1/main.db"), [("skype.tester1".to_string(), "Skype")]);
        assert!(v("Users/a/AppData/Roaming/Skype/My Skype Received Files/main.db").is_empty());
        assert_eq!(v("Program Files/Miranda IM/Profiles/coin_fan.dat"), [("coin_fan".to_string(), "Miranda IM")]);
    }
}
