//! Artefacts context: parsers for browser, registry, Windows and mail artefacts that turn
//! evidence bytes into timeline events, identities and host facts.

mod browser;
mod pidl;
mod registry;
mod results;
mod sqlite;
mod tag;
mod windows;
mod text;

pub use results::{ArtifactResults, Fact, IdentityKind, IdentityRecord};
