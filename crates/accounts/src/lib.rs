//! Accounts context: who used the machine and which services they had accounts on.
//!
//! Byte-level detectors find e-mail addresses and URLs anywhere on the disk (live files,
//! deleted space, swap). Artifact parsers (browsers, registry) feed richer identities later;
//! [`Service`] classification is shared by both.

mod detectors;
mod service;
mod text;

pub use detectors::{EmailDetector, UrlDetector, detectors};
pub use service::{Service, ServiceKind};
