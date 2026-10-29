//! Windows registry artefacts. One `regf` reader ([`hive::Hive`]); the hive type is decided from
//! its root keys so renamed or carved hives work too.

mod hive;
mod mru;
mod ntuser;
mod shellbags;
mod system;

use crate::results::{ArtifactResults, Recorder};
use hive::{Hive, Key};
use ntuser::NtUser;
use shellbags::ShellBags;
use strata_kernel::{Damage, DamageKind};
use strata_timeline::{CRYPTO_TAG, EventKind};
use system::{SamHive, SoftwareHive, SystemHive};

pub(crate) use hive::Hive as RegistryHive;

#[cfg(test)]
pub(crate) use hive::testutil as hive_testutil;

/// Wallet software keys (matched case-insensitively against key names).
const WALLET_KEYS: &[&str] = &["bitcoin", "bitcoin-qt", "bitcoin core", "electrum", "multibit", "armory", "litecoin", "namecoin"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HiveKind {
    NtUser,
    /// Per-user classes hive (UsrClass.dat): Vista+ shellbags.
    UsrClass,
    System,
    Software,
    Sam,
    Other,
}

impl HiveKind {
    fn detect(hive: &Hive<'_>) -> Self {
        let Some(root) = hive.root() else { return Self::Other };
        let names: Vec<String> = hive.subkeys(&root).into_iter().map(|k| k.name.to_ascii_lowercase()).collect();
        let has = |n: &str| names.iter().any(|x| x == n);
        if has("select") && names.iter().any(|n| n.starts_with("controlset")) {
            Self::System
        } else if has("sam") {
            Self::Sam
        } else if has("software") && (has("control panel") || has("environment") || has("console")) {
            Self::NtUser
        } else if has("local settings") {
            Self::UsrClass
        } else if has("microsoft") && (has("classes") || has("policies")) {
            Self::Software
        } else {
            Self::Other
        }
    }

    fn artifact(self) -> &'static str {
        match self {
            Self::NtUser => "registry.ntuser",
            Self::UsrClass => "registry.usrclass",
            Self::System => "registry.system",
            Self::Software => "registry.software",
            Self::Sam => "registry.sam",
            Self::Other => "registry.hive",
        }
    }
}

/// Parse any registry hive (shellbags are looked for in all of them).
pub(crate) fn parse_hive(data: &[u8]) -> ArtifactResults {
    let Some(hive) = Hive::parse(data) else {
        let mut out = ArtifactResults::default();
        out.damage.push(Damage::new(DamageKind::Corrupt, None, "not a registry hive"));
        return out;
    };
    let kind = HiveKind::detect(&hive);
    let mut rec = Recorder::new(kind.artifact());
    match kind {
        HiveKind::NtUser => NtUser::new(&hive).parse(&mut rec),
        HiveKind::System => SystemHive::new(&hive).parse(&mut rec),
        HiveKind::Software => SoftwareHive::new(&hive).parse(&mut rec),
        HiveKind::Sam => SamHive::new(&hive).parse(&mut rec),
        HiveKind::UsrClass | HiveKind::Other => {}
    }
    WalletKeys::new(&hive).scan(&mut rec);
    // Every hive is tried: renamed or carved user hives still carry their BagMRU keys.
    let bags = ShellBags::new(&hive).scan();
    for d in hive.take_damage() {
        rec.damage(d);
    }
    let mut out = rec.finish();
    out.merge(bags);
    out
}

/// Wallet software traces: `Software\Bitcoin\Bitcoin-Qt` (`strDataDir`), Electrum, MultiBit,
/// Armory keys, and the `bitcoin:` URL handler.
struct WalletKeys<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> WalletKeys<'h, 'a> {
    fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    fn scan(&self, rec: &mut Recorder) {
        for base in ["Software", "", "Software\\Wow6432Node", "Wow6432Node"] {
            let Some(parent) = self.hive.open(base) else { continue };
            for k in self.hive.subkeys(&parent) {
                if WALLET_KEYS.iter().any(|w| k.name.eq_ignore_ascii_case(w)) {
                    let path = if base.is_empty() { k.name.clone() } else { format!("{base}\\{}", k.name) };
                    self.walk(rec, &k, &path, 0);
                }
            }
        }
        for classes in ["Software\\Classes\\bitcoin", "Classes\\bitcoin"] {
            if let Some(k) = self.hive.open(classes) {
                self.report(rec, &k, classes, "bitcoin: URL handler registered");
            }
        }
    }

    fn walk(&self, rec: &mut Recorder, key: &Key, path: &str, depth: u8) {
        let values: Vec<String> = self.hive.values(key).iter().map(|v| format!("{}={}", v.name, v.display())).collect();
        self.report(rec, key, path, &values.join("; "));
        if depth < 3 {
            for sub in self.hive.subkeys(key) {
                self.walk(rec, &sub, &format!("{path}\\{}", sub.name), depth + 1);
            }
        }
    }

    fn report(&self, rec: &mut Recorder, key: &Key, path: &str, detail: &str) {
        if let Some(e) = rec.make(key.last_write, EventKind::WalletActivity, format!("Registry key {path}")) {
            rec.push(e.with_detail(format!("wallet software settings: {detail}")).with_tag(CRYPTO_TAG));
        }
        if let Some(dir) = detail.split("; ").find_map(|kv| kv.strip_prefix("strDataDir=")) {
            rec.fact("wallet_data_dir", dir.to_string());
        }
    }
}

#[cfg(test)]
mod tests;
