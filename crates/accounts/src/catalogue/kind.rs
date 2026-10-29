use serde::{Deserialize, Serialize};

/// What a catalogued service is. The order is the display order of the Accounts screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Exchange,
    WebWallet,
    Faucet,
    MiningPool,
    WalletSoftware,
    MiningSoftware,
    Gambling,
    Lending,
    Mixer,
    Marketplace,
    Payment,
    Explorer,
    Forum,
    Info,
    CloudStorage,
    Mail,
    Social,
    Im,
    Other,
}

impl ServiceKind {
    pub const ALL: [ServiceKind; 19] = [
        Self::Exchange,
        Self::WebWallet,
        Self::Faucet,
        Self::MiningPool,
        Self::WalletSoftware,
        Self::MiningSoftware,
        Self::Gambling,
        Self::Lending,
        Self::Mixer,
        Self::Marketplace,
        Self::Payment,
        Self::Explorer,
        Self::Forum,
        Self::Info,
        Self::CloudStorage,
        Self::Mail,
        Self::Social,
        Self::Im,
        Self::Other,
    ];

    /// Sentence-case label as the UI and reports show it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Exchange => "exchange",
            Self::WebWallet => "web wallet",
            Self::Faucet => "faucet",
            Self::MiningPool => "mining pool",
            Self::WalletSoftware => "wallet software",
            Self::MiningSoftware => "mining software",
            Self::Gambling => "dice and gambling",
            Self::Lending => "lending and investment",
            Self::Mixer => "mixer",
            Self::Marketplace => "marketplace",
            Self::Payment => "payment system",
            Self::Explorer => "block explorer",
            Self::Forum => "forum",
            Self::Info => "news and charts",
            Self::CloudStorage => "cloud storage",
            Self::Mail => "mail",
            Self::Social => "social network",
            Self::Im => "messenger",
            Self::Other => "other",
        }
    }

    /// Touches cryptocurrency directly (a visit is a crypto trace).
    pub fn is_crypto(self) -> bool {
        !matches!(self, Self::Payment | Self::CloudStorage | Self::Mail | Self::Social | Self::Im | Self::Other)
    }

    /// Worth reporting as a URL finding: crypto services plus e-money systems used to buy coins.
    pub fn is_reportable(self) -> bool {
        self.is_crypto() || self == Self::Payment
    }

    /// Holds or held money for the user: an account here may still have a balance or a
    /// withdrawal history to check.
    pub fn holds_funds(self) -> bool {
        matches!(
            self,
            Self::Exchange | Self::WebWallet | Self::Faucet | Self::MiningPool | Self::Gambling | Self::Lending | Self::Payment
        )
    }

    /// Timeline tag for events mentioning a service of this kind.
    pub fn tag(self) -> Option<&'static str> {
        match self {
            k if k.is_crypto() => Some("crypto"),
            Self::Payment => Some("payment"),
            Self::Mail => Some("mail"),
            Self::Social | Self::Im => Some("social"),
            Self::CloudStorage => Some("cloud"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups() {
        assert!(ServiceKind::Faucet.is_crypto() && ServiceKind::Faucet.holds_funds());
        assert!(ServiceKind::Payment.is_reportable() && !ServiceKind::Payment.is_crypto());
        assert!(!ServiceKind::Mail.is_reportable());
        assert_eq!(ServiceKind::Im.tag(), Some("social"));
        assert_eq!(ServiceKind::ALL.len(), 19);
    }
}
