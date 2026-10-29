//! User accounts of one installation, merged by name from the SAM, the profile list,
//! `/etc/passwd`, logon events and activity under each profile folder.

use crate::values::SourceRef;
use serde::Serialize;
use strata_artifacts::host::{UserRecord, stamp};
use strata_kernel::Timestamp;

/// Built-in Windows accounts that are not people unless they logged on.
const BUILTIN: &[&str] = &["administrator", "guest", "helpassistant", "defaultaccount", "wdagutilityaccount", "aspnet", "homegroupuser$"];

#[derive(Debug, Clone, Serialize)]
pub struct UserAccount {
    pub name: String,
    pub full_name: Option<String>,
    /// SID, `RID <n>` or `uid <n>`.
    pub id: Option<String>,
    pub home: Option<String>,
    #[serde(serialize_with = "stamp::serialize")]
    pub last_logon: Option<Timestamp>,
    /// SAM logon counter.
    pub logon_count: Option<u32>,
    #[serde(serialize_with = "stamp::serialize")]
    pub password_set: Option<Timestamp>,
    /// Latest user activity under the profile folder (browser, documents, programs).
    #[serde(serialize_with = "stamp::serialize")]
    pub last_activity: Option<Timestamp>,
    /// Logon events recorded for the account (event logs, wtmp).
    pub logon_events: u64,
    /// Built-in account (Administrator, Guest...) rather than a person's.
    pub builtin: bool,
    pub sources: Vec<SourceRef>,
}

impl UserAccount {
    fn new(name: &str) -> Self {
        let lower = name.to_lowercase();
        let builtin = BUILTIN.contains(&lower.as_str()) || lower.starts_with("support_") || lower.starts_with("iusr_") || lower.starts_with("iwam_");
        Self {
            name: name.to_string(),
            full_name: None,
            id: None,
            home: None,
            last_logon: None,
            logon_count: None,
            password_set: None,
            last_activity: None,
            logon_events: 0,
            builtin,
            sources: Vec::new(),
        }
    }

    /// Latest sign of the account being used.
    pub fn last_seen(&self) -> Option<Timestamp> {
        self.last_logon.max(self.last_activity)
    }
}

fn later(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    a.max(b)
}

/// Accounts keyed by name (case-insensitive).
#[derive(Default)]
pub(crate) struct UserBook {
    users: Vec<UserAccount>,
}

impl UserBook {
    fn entry(&mut self, name: &str) -> &mut UserAccount {
        let i = match self.users.iter().position(|u| u.name.eq_ignore_ascii_case(name)) {
            Some(i) => i,
            None => {
                self.users.push(UserAccount::new(name));
                self.users.len() - 1
            }
        };
        &mut self.users[i]
    }

    pub fn record(&mut self, r: UserRecord, source: SourceRef) {
        if r.name.trim().is_empty() {
            return;
        }
        let u = self.entry(r.name.trim());
        if r.id.as_deref().is_some_and(|id| id == "RID 500" || id == "RID 501") {
            u.builtin = true;
        }
        u.full_name = u.full_name.take().or(r.full_name);
        // A SID says more than `RID 1003`.
        if r.id.as_deref().is_some_and(|id| id.starts_with("S-1-")) || u.id.is_none() {
            u.id = r.id.or(u.id.take());
        }
        u.home = u.home.take().or(r.home);
        u.last_logon = later(later(u.last_logon, r.last_logon), r.profile_loaded);
        u.logon_count = u.logon_count.max(r.logon_count);
        u.password_set = later(u.password_set, r.password_set);
        if !u.sources.contains(&source) && u.sources.len() < 4 {
            u.sources.push(source);
        }
    }

    /// A logon event: raises the last logon and counts it.
    pub fn logon(&mut self, name: &str, last: Timestamp, count: u64) {
        let u = self.entry(name);
        u.last_logon = later(u.last_logon, Some(last));
        u.logon_events += count;
    }

    /// Activity under the user's profile folder.
    pub fn activity(&mut self, name: &str, last: Timestamp) {
        let u = self.entry(name);
        u.last_activity = later(u.last_activity, Some(last));
    }

    /// People first (most recently seen first), built-in accounts last.
    pub fn finish(mut self) -> Vec<UserAccount> {
        self.users.sort_by(|a, b| a.builtin.cmp(&b.builtin).then(b.last_seen().cmp(&a.last_seen())).then(a.name.cmp(&b.name)));
        self.users
    }
}

/// The account a logon event title names; `None` for logoffs, failures and system accounts.
///
/// Titles: `Login andrew` (wtmp), `Logon: DOM\user (type 2, interactive)` (Security log),
/// `Session logon: DOM\user from 10.0.0.2` (Terminal Services), `Windows logon: Admin` (SAM).
pub fn logon_user(title: &str) -> Option<String> {
    let rest = ["Login ", "Logon: ", "Session logon: ", "Session reconnected: ", "Windows logon: "].iter().find_map(|p| title.strip_prefix(p))?;
    let account = rest.split(" (").next()?.split(" from ").next()?.split(" by ").next()?.trim();
    let user = account.rsplit('\\').next()?.trim();
    let lower = user.to_lowercase();
    let system = ["system", "local service", "network service", "anonymous logon", "reboot", "runlevel", "logon"].contains(&lower.as_str());
    (!user.is_empty() && !user.ends_with('$') && !system && !lower.starts_with("dwm-") && !lower.starts_with("umfd-")).then(|| user.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_from_logon_titles() {
        assert_eq!(logon_user("Login andrew").as_deref(), Some("andrew"));
        assert_eq!(logon_user("Logon: HOME-PC\\Olga (type 2, interactive)").as_deref(), Some("Olga"));
        assert_eq!(logon_user("Session logon: HOME-PC\\Olga from 10.0.0.2").as_deref(), Some("Olga"));
        assert_eq!(logon_user("Windows logon: Admin").as_deref(), Some("Admin"));
        assert_eq!(logon_user("Logon: NT AUTHORITY\\SYSTEM (type 5, service)"), None);
        assert_eq!(logon_user("Logon: WORKGROUP\\HOME-PC$ (type 3, network)"), None);
        assert_eq!(logon_user("Logoff: HOME-PC\\Olga"), None);
        assert_eq!(logon_user("Failed logon: HOME-PC\\Olga"), None);
        assert_eq!(logon_user("Login reboot"), None);
    }

    #[test]
    fn book_merges_by_name_and_orders_people_first() {
        let src = SourceRef::new("registry.sam", "WINDOWS/system32/config/SAM");
        let mut book = UserBook::default();
        book.record(UserRecord { name: "Administrator".into(), id: Some("RID 500".into()), ..Default::default() }, src.clone());
        book.record(UserRecord { name: "olga".into(), id: Some("RID 1003".into()), logon_count: Some(9), ..Default::default() }, src.clone());
        book.record(UserRecord { name: "Olga".into(), id: Some("S-1-5-21-1-2-3-1003".into()), home: Some("C:\\Users\\Olga".into()), ..Default::default() }, src);
        book.activity("OLGA", Timestamp::from_unix_secs(1_300_000_000).unwrap());
        let users = book.finish();
        assert_eq!(users.len(), 2);
        assert_eq!((users[0].name.as_str(), users[0].id.as_deref(), users[0].logon_count), ("olga", Some("S-1-5-21-1-2-3-1003"), Some(9)));
        assert!(users[1].builtin && users[0].last_activity.is_some());
    }
}
