//! Timeline events read as crypto signals: a faucet visit, a wallet run, a wallet download, a
//! crypto search, use of an account, a money mail.

use crate::inputs::EventRecord;
use strata_accounts::{Service, ServiceKind};
use strata_crypto::WalletFileName;
use strata_kernel::{EvidenceId, Timestamp};
use strata_timeline::EventKind;

/// What kind of activity an event shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalClass {
    Faucet,
    Exchange,
    WebWallet,
    MiningPool,
    Gambling,
    OtherCryptoSite,
    Payment,
    WalletRun,
    WalletInstall,
    MiningRun,
    AccountUse,
    MoneyMail,
    WalletFile,
    Search,
    Other,
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub event_id: i64,
    pub evidence: EvidenceId,
    pub at: Timestamp,
    pub class: SignalClass,
    pub service: Option<Service>,
    /// Event title, for quoting searches and file names.
    pub subject: String,
}

impl Signal {
    /// `None` when the event says nothing crypto-relevant.
    pub fn of(record: &EventRecord) -> Option<Signal> {
        let e = &record.event;
        let service = Service::classify(e.title()).or_else(|| Service::classify(e.detail()));
        let wallet_file = WalletFileName::mentioned_in(e.title());
        let kind = service.map(|s| s.kind);
        let software = matches!(kind, Some(ServiceKind::WalletSoftware | ServiceKind::MiningSoftware));
        let class = match e.kind() {
            EventKind::ProgramRun | EventKind::WalletActivity if kind == Some(ServiceKind::MiningSoftware) => SignalClass::MiningRun,
            EventKind::ProgramRun | EventKind::WalletActivity if software || e.kind() == EventKind::WalletActivity => SignalClass::WalletRun,
            EventKind::Download | EventKind::ProgramInstalled if software => SignalClass::WalletInstall,
            EventKind::Email if e.has_tag("money") => SignalClass::MoneyMail,
            EventKind::AccountSeen | EventKind::Login | EventKind::FormInput | EventKind::Email if kind.is_some_and(ServiceKind::holds_funds) => {
                SignalClass::AccountUse
            }
            EventKind::Search if e.is_crypto() => SignalClass::Search,
            _ if wallet_file => SignalClass::WalletFile,
            EventKind::UrlVisited | EventKind::Cookie | EventKind::Download | EventKind::AccountSeen | EventKind::Login => {
                match kind? {
                    ServiceKind::Faucet => SignalClass::Faucet,
                    ServiceKind::Exchange => SignalClass::Exchange,
                    ServiceKind::WebWallet => SignalClass::WebWallet,
                    ServiceKind::MiningPool => SignalClass::MiningPool,
                    ServiceKind::Gambling => SignalClass::Gambling,
                    ServiceKind::Payment => SignalClass::Payment,
                    k if k.is_crypto() => SignalClass::OtherCryptoSite,
                    _ => return None,
                }
            }
            _ if e.is_crypto() && !e.kind().is_filesystem() => SignalClass::Other,
            _ => return None,
        };
        Some(Signal { event_id: record.id, evidence: record.evidence, at: e.at(), class, service, subject: e.title().to_string() })
    }

    /// Plain-language description (`visited the faucet FreeBitco.in`).
    pub fn describe(&self) -> String {
        let name = self.service.map(|s| s.name).unwrap_or("a crypto site");
        let quoted = || shorten(&self.subject, 60);
        match self.class {
            SignalClass::Faucet => format!("visited the faucet {name}"),
            SignalClass::Exchange => format!("visited the exchange {name}"),
            SignalClass::WebWallet => format!("used the web wallet {name}"),
            SignalClass::MiningPool => format!("visited the mining pool {name}"),
            SignalClass::Gambling => format!("visited the dice site {name}"),
            SignalClass::OtherCryptoSite => format!("visited {name}"),
            SignalClass::Payment => format!("used {name}"),
            SignalClass::WalletRun => format!("ran {}", self.service.map(|s| s.name).unwrap_or("wallet software")),
            SignalClass::WalletInstall => format!("downloaded or installed {}", self.service.map(|s| s.name).unwrap_or("wallet software")),
            SignalClass::MiningRun => format!("ran the miner {}", self.service.map(|s| s.name).unwrap_or("mining software")),
            SignalClass::AccountUse => format!("used an account on {name}"),
            SignalClass::MoneyMail => format!("got a money mail from {name}: \"{}\"", quoted()),
            SignalClass::WalletFile => format!("touched the wallet file {}", quoted()),
            SignalClass::Search => format!("searched for \"{}\"", quoted()),
            SignalClass::Other => format!("crypto activity \"{}\"", quoted()),
        }
    }
}

pub(crate) fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max - 1).collect::<String>()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_timeline::{CRYPTO_TAG, EventSource, TimelineEvent};

    fn rec(kind: EventKind, title: &str) -> EventRecord {
        let at = Timestamp::from_unix_secs(1_310_000_000).unwrap();
        EventRecord { id: 1, evidence: EvidenceId::new(1), event: TimelineEvent::new(at, kind, title, EventSource::new("t", "/x")).with_tag(CRYPTO_TAG) }
    }

    #[test]
    fn classifies_events() {
        let class = |k, t: &str| Signal::of(&rec(k, t)).map(|s| s.class);
        assert_eq!(class(EventKind::UrlVisited, "https://freebitco.in/?op=home"), Some(SignalClass::Faucet));
        assert_eq!(class(EventKind::UrlVisited, "https://mtgox.com/trade"), Some(SignalClass::Exchange));
        assert_eq!(class(EventKind::ProgramRun, "C:\\Program Files\\Bitcoin\\bitcoin-qt.exe"), Some(SignalClass::WalletRun));
        assert_eq!(class(EventKind::Download, "C:\\Users\\a\\Downloads\\electrum-1.9.7.exe"), Some(SignalClass::WalletInstall));
        assert_eq!(class(EventKind::ProgramRun, "D:\\miner\\cgminer.exe"), Some(SignalClass::MiningRun));
        assert_eq!(class(EventKind::Search, "bitcoin faucet"), Some(SignalClass::Search));
        assert_eq!(class(EventKind::DocumentOpened, "C:\\backup\\wallet.dat"), Some(SignalClass::WalletFile));
        assert_eq!(class(EventKind::UrlVisited, "https://vk.com/id1"), None);
        let faucet = Signal::of(&rec(EventKind::UrlVisited, "http://freebitcoins.appspot.com/")).unwrap();
        assert_eq!(faucet.describe(), "visited the faucet The Bitcoin Faucet (Gavin Andresen)");
    }
}
