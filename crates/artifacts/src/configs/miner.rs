use super::config_text;
use crate::results::{IdentityKind, Recorder};
use crate::text::{host_of, is_email};
use strata_accounts::Service;

/// Mining software configs and launch scripts (`cgminer.conf`, GUIMiner `poclbm.ini`,
/// `start.bat` with `-o stratum+tcp://… -u login.worker`): the pool and the pool login.
pub(crate) struct MinerConfig;

/// Keys / flags naming the pool (single-letter flags are case-sensitive: `-o` vs `-O`).
const POOL_KEYS: &[&str] = &["o", "url", "pool", "server", "host"];
/// Keys / flags naming the worker login.
const USER_KEYS: &[&str] = &["u", "user", "username", "login", "worker"];
/// `user:password` pairs.
const USERPASS_KEYS: &[&str] = &["O", "userpass"];

const MARKERS: &[&str] = &["stratum+tcp://", "cgminer", "bfgminer", "sgminer", "poclbm", "guiminer", "minerd", "cpuminer", "ccminer", "cudaminer", "ethminer", "xmrig"];

fn key_is(key: &str, keys: &[&str]) -> bool {
    keys.iter().any(|k| if k.len() == 1 { key == *k } else { key.eq_ignore_ascii_case(k) })
}

/// `(key, inline value, explicit)`: `--user=x` → (`user`, `x`, true); `"user":"x"` →
/// (`user`, `x`, true); `-u` → (`u`, None, true); plain words are not keys.
fn split_key(token: &str) -> (&str, Option<&str>, bool) {
    let dashed = token.trim_start_matches('-');
    let flag = dashed.len() < token.len();
    if let Some((k, v)) = dashed.split_once('=') {
        return (k, Some(v), true);
    }
    if let Some((k, v)) = dashed.split_once(':').filter(|(k, v)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphabetic()) && !v.starts_with('/')) {
        return (k, (!v.is_empty()).then_some(v), true);
    }
    (dashed, None, flag)
}

impl MinerConfig {
    pub fn looks_like(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        MARKERS.iter().any(|m| lower.contains(m)) && (lower.contains("-u") || lower.contains("user") || lower.contains("-o"))
    }

    /// Pools and logins in order of appearance.
    fn scan(text: &str) -> (Vec<String>, Vec<String>) {
        let cleaned: String = text.chars().map(|c| if "\"',{}[]".contains(c) { ' ' } else { c }).collect();
        let tokens: Vec<&str> = cleaned.split_whitespace().collect();
        let (mut pools, mut users) = (Vec::new(), Vec::new());
        let mut i = 0;
        while i < tokens.len() {
            let (key, inline, explicit) = split_key(tokens[i]);
            let colon = tokens.get(i + 1) == Some(&":");
            let next = tokens.get(i + 1 + usize::from(colon)).copied();
            let value = inline.or(if explicit || colon { next } else { None });
            if let Some(v) = value.filter(|v| !v.starts_with('-')) {
                if key_is(key, POOL_KEYS) && (v.contains("://") || v.contains('.')) {
                    pools.push(v.to_string());
                } else if key_is(key, USER_KEYS) {
                    users.push(v.to_string());
                } else if key_is(key, USERPASS_KEYS) {
                    users.extend(v.split(':').next().map(str::to_string));
                }
            }
            i += 1;
        }
        (pools, users)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = config_text(data);
        if !Self::looks_like(&text) {
            return;
        }
        let (pools, users) = Self::scan(&text);
        for p in &pools {
            rec.fact("mining_pool", p.clone());
        }
        for (i, user) in users.iter().enumerate() {
            let pool = pools.get(i).or(pools.last());
            let service = pool.map(|p| Service::classify_url(p).map(|s| s.name.to_string()).or_else(|| host_of(p)).unwrap_or_else(|| p.clone()));
            // Pools log in as `account.worker`; payout-to-address pools use the address itself.
            let account = if is_email(user) || !user.contains('.') { user.as_str() } else { user.split('.').next().unwrap_or(user) };
            let note = format!("mining pool login (worker {user})");
            rec.identity_noted(IdentityKind::Login, account, service.as_deref(), None, &note);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(data: &[u8]) -> Vec<(String, Option<String>)> {
        let mut rec = Recorder::new("miner.config");
        MinerConfig::parse(data, &mut rec);
        rec.finish().identities.into_iter().map(|i| (i.value, i.service)).collect()
    }

    #[test]
    fn cgminer_json_and_bat_scripts() {
        let conf = br#"{ "pools" : [ { "url" : "stratum+tcp://stratum.btcguild.com:3333", "user" : "miner_test_1", "pass" : "x" },
                       { "url":"http://mining.bitcoin.cz:8332", "user":"slush_tester.worker1", "pass":"x" } ], "intensity" : "9" }"#;
        assert_eq!(
            ids(conf),
            [("miner_test_1".to_string(), Some("BTC Guild".to_string())), ("slush_tester".to_string(), Some("Slush Pool".to_string()))]
        );
        let bat = b"@echo off\r\ncgminer.exe -o stratum+tcp://eu.ghash.io:3333 -u ghash_tester.1 -p x --intensity 8\r\npause\r\n";
        assert_eq!(ids(bat), [("ghash_tester".to_string(), Some("GHash.IO".to_string()))]);
        let guiminer = br#"{"profiles": [{"username": "gui_tester", "server": "mining.bitcoin.cz", "port": "8332", "name": "slush"}], "show_console": false} poclbm"#;
        assert_eq!(ids(guiminer), [("gui_tester".to_string(), Some("Slush Pool".to_string()))]);
        let userpass = b"bfgminer -o http://pool.example.org:8332 -O pool_tester:secret";
        assert_eq!(ids(userpass), [("pool_tester".to_string(), Some("pool.example.org".to_string()))]);
        assert!(ids(b"@echo off\r\ncopy a b\r\n").is_empty());
    }
}
