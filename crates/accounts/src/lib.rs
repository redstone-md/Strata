//! Accounts context: who used the machine and which services they had accounts on.
//!
//! The [`Catalogue`] (embedded `data/services.toml`) knows several hundred services of the
//! 2009–2018 era: faucets, exchanges, pools, wallets, forums, e-money, mail and messengers.
//! Byte-level detectors find e-mail addresses, service URLs and login values anywhere on the
//! disk; artefact parsers add saved logins, form history and mail accounts. The
//! [`AccountResolver`] merges all of them into [`Account`]s per service.

mod account;
mod catalogue;
mod detectors;
mod service;
mod text;
mod cyrillic;
mod url;
mod url_accounts;

pub use account::{Account, AccountResolver, AccountSource, BULK_PLACE_ADDRESSES, IdentifierKind, Observation, SourceRef, Standing, TraceKind};
pub use catalogue::{Catalogue, ServiceEntry, ServiceGroup, ServiceKind, Years};
pub use detectors::{EmailDetector, LoginDetector, UrlDetector, detectors};
pub use service::Service;
pub use cyrillic::{decode_utf8_or_cp1251, repair_mojibake};
pub use url::{host_of, percent_decode};
pub use url_accounts::{LOGIN_FIELDS, UrlAccount, UrlAccounts};
