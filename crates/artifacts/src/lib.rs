//! Artefacts context: parsers for browser, registry, Windows and mail artefacts that turn
//! evidence bytes into timeline events, identities and host facts.

mod browser;
mod registry;
mod results;
mod sqlite;
mod tag;
mod text;

pub use results::{ArtifactResults, Fact, IdentityKind, IdentityRecord};
