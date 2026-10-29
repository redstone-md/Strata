//! Where a file sits says whose it is: a user's profile, a browser's or mail client's data, or
//! the operating system and installed software (whose e-mails and keys belong to strangers).

/// Kind of place a path points into. Ordered from least to most telling about the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathClass {
    /// Operating system, installed programs, package lists, documentation.
    System,
    Other,
    /// Inside a user profile folder.
    Profile,
    /// Browser data in a profile (saved logins, history, cookies, form data).
    Browser,
    /// A mail client's store or settings.
    MailClient,
}

/// Leading folders of system and software trees (lower case, `/`-separated, no drive).
const SYSTEM_ROOTS: &[&str] = &[
    "windows/",
    "winnt/",
    "program files",
    "programdata/",
    "msocache/",
    "i386/",
    "system volume information/",
    "$",
    "usr/",
    "lib/",
    "lib64/",
    "opt/",
    "etc/",
    "bin/",
    "sbin/",
    "boot/",
    "var/lib/",
    "var/cache/",
    "var/log/",
    "snap/",
    "applications/",
    "library/",
    "system/",
    "private/var/",
];
/// Folders that hold other people's text wherever they are.
const SYSTEM_PARTS: &[&str] = &[
    "/site-packages/",
    "/dist-packages/",
    "/node_modules/",
    "/vendor/",
    "/share/doc/",
    "/locale/",
    "/.cache/",
    "/temporary internet files/content.ie5/",
    "/appdata/local/temp/",
    "/local settings/temp/",
    "/.git/",
    "/.m2/",
    "/.cargo/registry/",
];
const PROFILE_ROOTS: &[&str] = &["users/", "documents and settings/", "home/"];
/// Profile folders that belong to nobody in particular.
const SHARED_PROFILES: &[&str] = &["public", "default", "default user", "all users", "administrator", "guest", "localservice", "networkservice", "defaultapppool"];
const BROWSER_PARTS: &[&str] = &[
    "/google/chrome/",
    "/chromium/",
    "/mozilla/firefox/",
    "/opera software/",
    "/opera/",
    "/yandex/yandexbrowser/",
    "/microsoft/edge/",
    "/internet explorer/",
    "/microsoft/windows/inetcookies",
    "/cookies/",
    "/.mozilla/",
    "/.config/google-chrome/",
    "/vivaldi/",
    "/comodo/dragon/",
];
const MAIL_PARTS: &[&str] = &["/thunderbird/", "/outlook express/", "/microsoft/outlook/", "/the bat!/", "/.thunderbird/", "/windows mail/", "/windows live mail/", "/mail/", "/opera mail/"];
const MAIL_ENDINGS: &[&str] = &[".dbx", ".pst", ".ost", ".mbox", ".eml", ".msf"];

/// `C:\Users\Olga\…` and `/home/olga/…` alike: lower case, `/`, no drive or leading slash.
fn normalise(path: &str) -> String {
    let p = path.replace('\\', "/").to_lowercase();
    let p = p.trim_start_matches('/');
    let p = match p.as_bytes() {
        [_, b':', b'/', ..] => &p[3..],
        _ => p,
    };
    p.to_string()
}

/// The profile folder name of a path inside a user profile (`olga` for `Users/Olga/…`).
pub fn profile_name(path: &str) -> Option<String> {
    let p = normalise(path);
    let rest = PROFILE_ROOTS.iter().find_map(|root| p.strip_prefix(root))?;
    let name = rest.split('/').next().filter(|n| !n.is_empty() && rest.len() > n.len())?;
    (!SHARED_PROFILES.contains(&name)).then(|| name.to_string())
}

pub fn classify(path: &str) -> PathClass {
    let p = normalise(path);
    let framed = format!("/{p}");
    if SYSTEM_ROOTS.iter().any(|r| p.starts_with(r)) || SYSTEM_PARTS.iter().any(|s| framed.contains(s)) {
        return PathClass::System;
    }
    if profile_name(path).is_none() {
        return PathClass::Other;
    }
    if MAIL_PARTS.iter().any(|s| framed.contains(s)) || MAIL_ENDINGS.iter().any(|e| p.ends_with(e)) {
        PathClass::MailClient
    } else if BROWSER_PARTS.iter().any(|s| framed.contains(s)) {
        PathClass::Browser
    } else {
        PathClass::Profile
    }
}

/// The last component of a path.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_places() {
        assert_eq!(classify("var/lib/dpkg/status"), PathClass::System);
        assert_eq!(classify("C:\\Program Files\\Mozilla Firefox\\omni.ja"), PathClass::System);
        assert_eq!(classify("/usr/share/doc/libc6/copyright"), PathClass::System);
        assert_eq!(classify("Users/olga/AppData/Roaming/npm/node_modules/x/package.json"), PathClass::System);
        assert_eq!(classify("Users/Olga/AppData/Local/Google/Chrome/User Data/Default/Login Data"), PathClass::Browser);
        assert_eq!(classify("Documents and Settings/olga/Local Settings/Application Data/Identities/{X}/Microsoft/Outlook Express/Inbox.dbx"), PathClass::MailClient);
        assert_eq!(classify("home/olga/.thunderbird/x.default/prefs.js"), PathClass::MailClient);
        assert_eq!(classify("Users/olga/Desktop/keys.txt"), PathClass::Profile);
        assert_eq!(classify("Users/Public/Documents/readme.txt"), PathClass::Other);
        assert_eq!(classify("backup/keys.txt"), PathClass::Other);
    }

    #[test]
    fn names_profiles() {
        assert_eq!(profile_name("C:/Users/Olga/Desktop/a.txt").as_deref(), Some("olga"));
        assert_eq!(profile_name("Documents and Settings/All Users/x"), None);
        assert_eq!(profile_name("home/ivan"), None, "the folder itself is not inside it");
        assert_eq!(file_name("Users/olga/Desktop/keys.txt"), "keys.txt");
        assert_eq!(file_name("C:\\a\\wallet.dat"), "wallet.dat");
    }
}
