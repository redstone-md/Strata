//! Wallet software data folders on Linux (`~/.bitcoin`, `~/.electrum`, `~/.multibit`,
//! `~/.armory`, `~/.litecoin`). Bitcoin Core's `debug.log` lines start with a timestamp, so
//! the first and last line date when the client ran.

use crate::results::Recorder;
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

/// Folder fragment → wallet software.
pub(crate) const WALLET_DIRS: &[(&str, &str)] = &[
    ("/.bitcoin/", "Bitcoin Core"),
    ("/.electrum/", "Electrum"),
    ("/.multibit/", "MultiBit"),
    ("/.multibit-hd/", "MultiBit HD"),
    ("/.armory/", "Armory"),
    ("/.litecoin/", "Litecoin Core"),
    ("/.config/exodus/", "Exodus"),
];

pub(crate) struct WalletDir;

impl WalletDir {
    pub fn software(path: &str) -> Option<&'static str> {
        let p = format!("/{}", path.to_lowercase());
        WALLET_DIRS.iter().find(|(dir, _)| p.contains(dir)).map(|(_, name)| *name)
    }

    /// `debug.log` (or any wallet folder file): record the folder, date the client runs.
    pub fn parse(path: &str, data: &[u8], rec: &mut Recorder) {
        let software = Self::software(path).unwrap_or("wallet software");
        rec.fact("wallet_data_dir", format!("{software}: {path}"));
        if !path.to_lowercase().ends_with("debug.log") {
            return;
        }
        let text = String::from_utf8_lossy(data);
        let stamps: Vec<Timestamp> = text.lines().filter_map(Timestamp::parse_iso8601).collect();
        let detail = format!("{software} debug.log, {} timestamped lines", stamps.len());
        if let (Some(first), Some(last)) = (stamps.first(), stamps.last()) {
            rec.dated(Some(*first), EventKind::WalletActivity, format!("{software} log starts"), detail.clone());
            rec.dated(Some(*last), EventKind::WalletActivity, format!("{software} log ends"), detail);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_log_dates_client_runs() {
        let log = b"2013-05-01 10:00:00 Bitcoin version v0.8.1\nnoise\n2013-06-02 08:15:01 Shutdown: done\n";
        let mut rec = Recorder::new("linux.wallet_dir");
        WalletDir::parse("home/u/.bitcoin/debug.log", log, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[1].at().to_string(), "2013-06-02 08:15:01");
        assert!(out.facts.iter().any(|f| f.key == "wallet_data_dir"));
    }
}
