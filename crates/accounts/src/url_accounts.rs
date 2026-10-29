//! Account identifiers carried by URLs and form-encoded data: `?login=`, `&username=`,
//! `email=`, Bitcointalk `action=profile;u=123`, and profile paths (`/user/<name>`) of known
//! services. Shared by the byte-level [`crate::LoginDetector`] and the artefact parsers.

use crate::account::IdentifierKind;
use crate::service::Service;

/// Query/form field names that carry an account name, and what they carry. Data table: the
/// single place to extend.
pub const LOGIN_FIELDS: &[(&str, IdentifierKind)] = &[
    ("login", IdentifierKind::Login),
    ("user", IdentifierKind::Login),
    ("username", IdentifierKind::Login),
    ("user_name", IdentifierKind::Login),
    ("user_login", IdentifierKind::Login),
    ("uname", IdentifierKind::Login),
    ("nick", IdentifierKind::Nickname),
    ("nickname", IdentifierKind::Nickname),
    ("account", IdentifierKind::Login),
    ("email", IdentifierKind::Email),
    ("e-mail", IdentifierKind::Email),
    ("mail", IdentifierKind::Email),
    ("userid", IdentifierKind::UserId),
    ("user_id", IdentifierKind::UserId),
    ("wmid", IdentifierKind::UserId),
];

/// Path segments followed by a user name on profile pages.
const PROFILE_SEGMENTS: &[&str] = &["user", "users", "u", "profile", "profiles", "member", "members", "account", "id"];

/// Values that are form placeholders or UI words, not accounts.
const NOT_ACCOUNTS: &[&str] = &[
    "null", "undefined", "true", "false", "none", "guest", "anonymous", "login", "logout", "user", "username", "email",
    "edit", "settings", "profile", "register", "signup", "password", "admin", "test", "me", "self", "new", "search",
];

/// An account named by a URL or form value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlAccount {
    pub service: Option<Service>,
    pub kind: IdentifierKind,
    pub value: String,
    /// The field or path segment it came from (`login`, `u`, `/user/`).
    pub field: String,
}

pub struct UrlAccounts;

impl UrlAccounts {
    /// Field kind for a query/form field name (case-insensitive).
    pub fn field_kind(name: &str) -> Option<IdentifierKind> {
        LOGIN_FIELDS.iter().find(|(f, _)| f.eq_ignore_ascii_case(name)).map(|(_, k)| *k)
    }

    /// Field kind for a form / autofill / cookie name, loosely (`user_login`, `LoginName`,
    /// `remember_email`). Password fields never qualify.
    pub fn form_field_kind(name: &str) -> Option<IdentifierKind> {
        let n = name.to_ascii_lowercase();
        if n.contains("pass") || n.contains("pwd") || n.contains("token") || n.contains("session") {
            return None;
        }
        Self::field_kind(&n).or(if n.contains("mail") {
            Some(IdentifierKind::Email)
        } else if n.contains("login") || n.contains("user") || n.contains("account") {
            Some(IdentifierKind::Login)
        } else if n.contains("nick") {
            Some(IdentifierKind::Nickname)
        } else {
            None
        })
    }

    /// Percent-decode (`%40` → `@`), trim, and reject placeholders and binary noise.
    pub fn clean_value(raw: &str, kind: IdentifierKind) -> Option<String> {
        let decoded = percent_decode(raw);
        let v = decoded.trim().trim_matches(['"', '\'']);
        let plausible = (2..=64).contains(&v.len())
            && v.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_@+".contains(&b))
            && v.bytes().any(|b| b.is_ascii_alphanumeric())
            && !NOT_ACCOUNTS.iter().any(|n| n.eq_ignore_ascii_case(v));
        let shape = match kind {
            IdentifierKind::Email => looks_like_email(v),
            IdentifierKind::UserId => v.bytes().all(|b| b.is_ascii_alphanumeric()),
            _ => v.len() >= 3 && !v.contains('@') || looks_like_email(v),
        };
        (plausible && shape).then(|| v.to_string())
    }

    /// Every account a URL names, on a known service only (`None` service = not catalogued).
    pub fn extract(url: &str) -> Vec<UrlAccount> {
        let Some(service) = Service::classify_url(url) else { return Vec::new() };
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let (path, query) = rest.split_once(['?', ';']).map_or((rest, ""), |(p, q)| (p, q));
        let query = query.split('#').next().unwrap_or_default();
        let mut out = Vec::new();
        let mut push = |kind, value: Option<String>, field: &str| {
            if let Some(value) = value.filter(|v| !out.iter().any(|a: &UrlAccount| a.value.eq_ignore_ascii_case(v))) {
                out.push(UrlAccount { service: Some(service), kind, value, field: field.to_string() });
            }
        };
        let params: Vec<(&str, &str)> = query.split(['&', ';']).filter_map(|p| p.split_once('=')).collect();
        let profile_page = params.iter().any(|(k, v)| k.eq_ignore_ascii_case("action") && v.eq_ignore_ascii_case("profile"));
        for (key, value) in &params {
            if let Some(kind) = Self::field_kind(key) {
                push(kind, Self::clean_value(value, kind), key);
            } else if profile_page && key.eq_ignore_ascii_case("u") {
                push(IdentifierKind::UserId, Self::clean_value(value, IdentifierKind::UserId), "u");
            }
        }
        let segments: Vec<&str> = path.split('/').skip(1).filter(|s| !s.is_empty()).collect();
        for pair in segments.windows(2) {
            if PROFILE_SEGMENTS.iter().any(|s| s.eq_ignore_ascii_case(pair[0])) {
                let kind = if pair[1].bytes().all(|b| b.is_ascii_digit()) { IdentifierKind::UserId } else { IdentifierKind::Login };
                push(kind, Self::clean_value(pair[1], kind), &format!("/{}/", pair[0]));
            }
        }
        out
    }
}

pub(crate) fn looks_like_email(v: &str) -> bool {
    v.split_once('@').is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |j: usize| bytes.get(j).and_then(|b| (*b as char).to_digit(16));
        match (bytes[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(url: &str) -> Vec<(String, IdentifierKind, String)> {
        UrlAccounts::extract(url).into_iter().map(|a| (a.value, a.kind, a.service.map(|s| s.id.to_string()).unwrap_or_default())).collect()
    }

    #[test]
    fn query_and_profile_accounts() {
        assert_eq!(found("https://bitcointalk.org/index.php?action=profile;u=123456"), [("123456".into(), IdentifierKind::UserId, "bitcointalk".into())]);
        assert!(found("https://bitcointalk.org/index.php?topic=5;u=99").is_empty());
        assert_eq!(found("https://mtgox.com/login?username=satoshi_fan&x=1")[0].0, "satoshi_fan");
        assert_eq!(found("http://www.btc-e.com/profile?email=ivan.test%40mail.ru")[0], ("ivan.test@mail.ru".into(), IdentifierKind::Email, "btce".into()));
        assert_eq!(found("https://localbitcoins.com/accounts/profile/trader_test/")[0].0, "trader_test");
        assert_eq!(found("https://www.reddit.com/user/coin_tester_1/")[0].0, "coin_tester_1");
    }

    #[test]
    fn rejects_noise_and_unknown_sites() {
        assert!(found("https://example.com/?login=someone").is_empty());
        assert!(found("https://mtgox.com/?login=null&user=%25s").is_empty());
        assert!(found("https://mtgox.com/user/settings").is_empty());
        assert_eq!(UrlAccounts::clean_value("a", IdentifierKind::Login), None);
        assert_eq!(UrlAccounts::clean_value("x@y", IdentifierKind::Email), None);
    }
}
