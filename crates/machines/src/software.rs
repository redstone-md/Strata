//! Crypto-relevant software of one installation: wallets and miners recognised by the shared
//! service catalogue in installed-program lists, program runs and wallet traces, plus wallet
//! data folders.

use crate::values::SourceRef;
use serde::Serialize;
use strata_accounts::{Service, ServiceKind};
use strata_artifacts::host::stamp;
use strata_kernel::Timestamp;

/// What a program event says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProgramEvidence {
    Installed,
    Ran,
    /// Wallet registry keys, client logs, `bitcoin:` handler.
    WalletTrace,
}

/// Program events of one title from one file, aggregated.
#[derive(Debug, Clone)]
pub struct ProgramRow {
    pub volume: Option<u32>,
    pub path: String,
    pub artifact: String,
    pub evidence: ProgramEvidence,
    pub title: String,
    pub first: Timestamp,
    pub last: Timestamp,
    pub count: u64,
    /// The event was tagged crypto-related when it was parsed.
    pub crypto: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoSoftware {
    pub name: String,
    /// `wallet software`, `mining software` or `crypto` (tagged but not catalogued).
    pub kind: String,
    #[serde(serialize_with = "stamp::serialize")]
    pub installed: Option<Timestamp>,
    #[serde(serialize_with = "stamp::serialize")]
    pub first_used: Option<Timestamp>,
    #[serde(serialize_with = "stamp::serialize")]
    pub last_used: Option<Timestamp>,
    /// Runs and wallet traces counted.
    pub uses: u64,
    pub data_dirs: Vec<String>,
    pub sources: Vec<SourceRef>,
}

impl CryptoSoftware {
    fn new(name: &str, kind: &str) -> Self {
        Self { name: name.into(), kind: kind.into(), installed: None, first_used: None, last_used: None, uses: 0, data_dirs: Vec::new(), sources: Vec::new() }
    }
}

/// Software name and kind for a program title; `None` when it is not crypto-related.
fn classify(title: &str, crypto: bool, evidence: ProgramEvidence) -> Option<(String, &'static str)> {
    let file = title.rsplit(['\\', '/']).next().unwrap_or(title);
    let service = Service::classify(title).or_else(|| Service::classify(file));
    match service.map(|s| (s, s.kind)) {
        Some((s, ServiceKind::WalletSoftware)) => Some((s.name.to_string(), "wallet software")),
        Some((s, ServiceKind::MiningSoftware)) => Some((s.name.to_string(), "mining software")),
        // Tagged installs that the catalogue does not know (`Bitcoin 0.3.21`) keep their name.
        _ if crypto && evidence == ProgramEvidence::Installed => Some((title.trim().to_string(), "crypto")),
        _ => None,
    }
}

#[derive(Default)]
pub(crate) struct SoftwareBook {
    items: Vec<CryptoSoftware>,
}

impl SoftwareBook {
    fn entry(&mut self, name: &str, kind: &str) -> &mut CryptoSoftware {
        let i = match self.items.iter().position(|s| s.name.eq_ignore_ascii_case(name)) {
            Some(i) => i,
            None => {
                self.items.push(CryptoSoftware::new(name, kind));
                self.items.len() - 1
            }
        };
        &mut self.items[i]
    }

    pub fn program(&mut self, row: &ProgramRow) {
        let Some((name, kind)) = classify(&row.title, row.crypto, row.evidence) else { return };
        let s = self.entry(&name, kind);
        match row.evidence {
            ProgramEvidence::Installed => s.installed = Some(s.installed.map_or(row.first, |t| t.min(row.first))),
            ProgramEvidence::Ran | ProgramEvidence::WalletTrace => {
                s.first_used = Some(s.first_used.map_or(row.first, |t| t.min(row.first)));
                s.last_used = s.last_used.max(Some(row.last));
                s.uses += row.count;
            }
        }
        let source = SourceRef::new(row.artifact.clone(), row.path.clone());
        if !s.sources.contains(&source) && s.sources.len() < 4 {
            s.sources.push(source);
        }
    }

    /// `wallet_data_dir` fact: `Electrum: home/u/.electrum/...` or a bare registry path.
    pub fn data_dir(&mut self, value: &str, source: SourceRef) {
        let (name, dir) = match value.split_once(": ") {
            Some((name, dir)) if !name.contains(['\\', '/']) => (name.to_string(), dir.to_string()),
            _ => (Service::classify(value).map_or_else(|| "Bitcoin Core".to_string(), |s| s.name.to_string()), value.to_string()),
        };
        let name = Service::classify(&name).filter(|s| s.kind == ServiceKind::WalletSoftware).map_or(name, |s| s.name.to_string());
        let s = self.entry(&name, "wallet software");
        // A folder path names the folder; files in it are listed once.
        let folder = dir.rsplit_once(['/', '\\']).filter(|_| dir.contains('.')).map_or(dir.as_str(), |(d, _)| d).to_string();
        if !s.data_dirs.iter().any(|d| d.eq_ignore_ascii_case(&folder)) && s.data_dirs.len() < 8 {
            s.data_dirs.push(folder);
        }
        if !s.sources.contains(&source) && s.sources.len() < 4 {
            s.sources.push(source);
        }
    }

    /// Wallets first, then by first sign of use.
    pub fn finish(mut self) -> Vec<CryptoSoftware> {
        let first = |s: &CryptoSoftware| s.installed.or(s.first_used);
        self.items.sort_by(|a, b| a.kind.cmp(&b.kind).reverse().then(first(a).cmp(&first(b))).then(a.name.cmp(&b.name)));
        self.items
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(evidence: ProgramEvidence, title: &str, secs: i64, crypto: bool) -> ProgramRow {
        let at = Timestamp::from_unix_secs(secs).unwrap();
        ProgramRow { volume: Some(1), path: "x".into(), artifact: "t".into(), evidence, title: title.into(), first: at, last: at, count: 2, crypto }
    }

    #[test]
    fn wallets_and_miners_from_programs_and_folders() {
        let mut book = SoftwareBook::default();
        book.program(&row(ProgramEvidence::Installed, "Electrum", 1_330_000_000, true));
        book.program(&row(ProgramEvidence::Ran, "%ProgramFiles%\\Electrum\\electrum.exe", 1_340_000_000, true));
        book.program(&row(ProgramEvidence::Ran, "C:\\miners\\cgminer.exe", 1_335_000_000, false));
        book.program(&row(ProgramEvidence::Installed, "Bitcoin 0.3.21", 1_290_000_000, true));
        book.program(&row(ProgramEvidence::Ran, "notepad.exe", 1_290_000_000, false));
        book.data_dir("Electrum: home/u/.electrum/wallets/default_wallet", SourceRef::new("linux.wallet_dir", "home/u/.electrum/wallets/default_wallet"));
        book.data_dir("D:\\BitcoinData", SourceRef::new("registry.ntuser", "NTUSER.DAT"));
        let items = book.finish();
        let names: Vec<&str> = items.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["Bitcoin Core (Bitcoin-Qt, bitcoind)", "Electrum", "CGMiner", "Bitcoin 0.3.21"]);
        let electrum = &items[1];
        assert_eq!((electrum.uses, electrum.data_dirs.clone()), (2, vec!["home/u/.electrum/wallets".to_string()]));
        assert!(electrum.installed.is_some() && electrum.last_used.is_some());
        assert_eq!(items[0].data_dirs, ["D:\\BitcoinData"]);
    }
}
