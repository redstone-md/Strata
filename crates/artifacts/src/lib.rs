//! Artefacts context: parsers for browser, registry, Windows and mail artefacts that turn
//! evidence bytes into timeline events, identities and host facts.
//!
//! Parsers work on byte slices and never panic on hostile input; whatever is recovered is
//! returned together with [`strata_kernel::Damage`]. [`ArtifactExtractor`] walks a
//! [`strata_fs::FileSystem`] (deleted and orphan entries included), [`parse_bytes`] handles
//! carved files, and [`fs_events`] turns filesystem MACB times into timeline events.
//!
//! Covered: Chromium-family History / Login Data / Web Data / Cookies, Firefox places /
//! formhistory / cookies / signons / logins.json, IE `index.dat`, Opera Presto history,
//! registry hives (NTUSER, UsrClass shellbags, SYSTEM, SOFTWARE, SAM, wallet keys), LNK, Prefetch, Recycle Bin
//! INFO2/$I, XP `.evt` and Vista+ `.evtx` logs (also carved chunks), Outlook Express `.dbx`, mbox/eml, IM account paths.

mod browser;
mod configs;
mod extract;
pub mod host;
mod linux;
mod mail;
mod pidl;
mod registry;
mod results;
mod sqlite;
mod tag;
mod text;
mod url_identities;
mod windows;

pub use extract::{ArtifactExtractor, ArtifactKind, FsEvents, ProfileHints, fs_events, parse_bytes, profile_of};
pub use results::{ArtifactResults, Fact, IdentityKind, IdentityRecord};
