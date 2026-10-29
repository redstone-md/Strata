use super::config_text;
use crate::results::{IdentityKind, Recorder};
use crate::text::is_email;
use std::collections::BTreeMap;

/// Mozilla `prefs.js`: Thunderbird mail identities and server logins, Firefox Sync account,
/// download folder.
pub(crate) struct MozillaPrefs;

/// `user_pref("key", "value");` → `(key, value)` for string prefs.
fn pref(line: &str) -> Option<(String, String)> {
    let body = line.trim().strip_prefix("user_pref(")?.trim_end().strip_suffix(");")?;
    let (key, value) = body.split_once(',')?;
    let unquote = |s: &str| s.trim().strip_prefix('"').and_then(|v| v.strip_suffix('"')).map(|v| v.replace("\\\\", "\\"));
    Some((unquote(key)?.to_ascii_lowercase(), unquote(value)?))
}

impl MozillaPrefs {
    pub fn looks_like(text: &str) -> bool {
        text.contains("user_pref(")
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = config_text(data);
        // mail.server.<id>.{username,hostname}
        let mut servers: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
        for (key, value) in text.lines().filter_map(pref) {
            let parts: Vec<&str> = key.split('.').collect();
            match parts.as_slice() {
                ["mail", "identity", _, "useremail"] => {
                    rec.identity_noted(IdentityKind::Email, &value, None, None, "mail identity (prefs.js)")
                }
                ["mail", "identity", _, "fullname"] => rec.fact("mail_identity_name", value),
                ["mail", "server", id, "username"] => servers.entry(id.to_string()).or_default().0 = Some(value),
                ["mail", "server", id, "hostname" | "realhostname"] => {
                    servers.entry(id.to_string()).or_default().1.get_or_insert(value);
                }
                ["services", "sync", "username" | "account"] => {
                    let kind = if is_email(&value) { IdentityKind::Email } else { IdentityKind::Login };
                    rec.identity_noted(kind, &value, Some("Firefox Sync"), None, "Firefox Sync account (prefs.js)");
                }
                ["browser", "download", "dir" | "lastdir"] => rec.fact("download_dir", value),
                _ => {}
            }
        }
        for (user, host) in servers.into_values() {
            let Some(user) = user.filter(|u| !u.trim().is_empty()) else { continue };
            let host = host.filter(|h| !h.is_empty() && h != "Local Folders");
            let kind = if is_email(&user) { IdentityKind::Email } else { IdentityKind::Login };
            let note = format!("mail server login{} (prefs.js)", host.as_deref().map(|h| format!(" on {h}")).unwrap_or_default());
            rec.identity_noted(kind, &user, host.as_deref(), None, &note);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thunderbird_and_sync_accounts() {
        let prefs = br#"// Mozilla User Preferences
user_pref("mail.identity.id1.useremail", "anna.test3@mail.ru");
user_pref("mail.identity.id1.fullName", "Anna Test");
user_pref("mail.server.server2.hostname", "pop.mail.ru");
user_pref("mail.server.server2.userName", "anna.test3");
user_pref("mail.server.server1.hostname", "Local Folders");
user_pref("mail.server.server1.userName", "nobody");
user_pref("services.sync.username", "olga.test1@yandex.ru");
user_pref("browser.download.dir", "C:\\Users\\a\\Downloads");
user_pref("mail.server.server2.check_new_mail", true);
"#;
        assert!(MozillaPrefs::looks_like(&String::from_utf8_lossy(prefs)));
        let mut rec = Recorder::new("mozilla.prefs");
        MozillaPrefs::parse(prefs, &mut rec);
        let out = rec.finish();
        let ids: Vec<_> = out.identities.iter().map(|i| (i.value.as_str(), i.service.as_deref())).collect();
        assert!(ids.contains(&("anna.test3@mail.ru", None)));
        assert!(ids.contains(&("anna.test3", Some("pop.mail.ru"))));
        assert!(ids.contains(&("nobody", None)));
        assert!(ids.contains(&("olga.test1@yandex.ru", Some("Firefox Sync"))));
        assert!(out.facts.iter().any(|f| f.key == "download_dir" && f.value == "C:\\Users\\a\\Downloads"));
    }
}
