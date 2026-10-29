use serde::{Deserialize, Serialize};

/// The sections of the Accounts screen: what an account could be worth to the owner's
/// recovery. Several [`super::ServiceKind`]s fold into one section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceGroup {
    /// Exchanges, web wallets, pools, faucets, crypto forums and software.
    Crypto,
    /// Banks and e-money systems (WebMoney, QIWI, Yandex.Money, PayPal...).
    Money,
    Mail,
    /// Cloud storage, notes and password managers: where wallet backups may sit.
    Cloud,
    /// Messengers and social networks.
    Social,
    Games,
    Shopping,
    Other,
}

impl ServiceGroup {
    /// Display order.
    pub const ALL: [ServiceGroup; 8] = [Self::Crypto, Self::Money, Self::Mail, Self::Cloud, Self::Social, Self::Games, Self::Shopping, Self::Other];

    pub fn label(self) -> &'static str {
        match self {
            Self::Crypto => "Crypto",
            Self::Money => "Money",
            Self::Mail => "E-mail",
            Self::Cloud => "Cloud & backups",
            Self::Social => "Messengers & social",
            Self::Games => "Games",
            Self::Shopping => "Shopping",
            Self::Other => "Other",
        }
    }

    /// Stable lowercase key (stored with each account, accepted by the MCP tool).
    pub fn id(self) -> &'static str {
        match self {
            Self::Crypto => "crypto",
            Self::Money => "money",
            Self::Mail => "mail",
            Self::Cloud => "cloud",
            Self::Social => "social",
            Self::Games => "games",
            Self::Shopping => "shopping",
            Self::Other => "other",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.id() == id.trim().to_ascii_lowercase())
    }

    /// An account here may hold money or point at a wallet backup.
    pub fn may_hold_value(self) -> bool {
        matches!(self, Self::Crypto | Self::Money | Self::Mail | Self::Cloud)
    }
}
