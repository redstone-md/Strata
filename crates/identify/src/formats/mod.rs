//! Per-format knowledge: header validators, structure walkers and length measurement.
//! Everything works on possibly truncated or damaged bytes and never panics.

pub mod archive;
pub mod bdb;
pub mod deflate;
pub mod document;
pub mod exec;
pub mod image;
pub mod mail;
pub mod measure;
pub mod media;
pub mod ole;
mod rar;
pub mod sqlite;
pub mod system;
mod tar;
pub mod wallet;
pub mod zip;

pub use rar::{walk4 as rar4_walk, walk5 as rar5_walk};
pub use tar::{TarMember, members as tar_members, walk as tar_walk};

use strata_kernel::Damage;

/// Result of walking a format's block/record chain.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    /// Offset just past the last structure when the format's end marker was reached.
    pub end: Option<u64>,
    /// (name, size) of members/records found.
    pub items: Vec<(String, u64)>,
    pub ok: usize,
    pub bad: usize,
    pub encrypted: usize,
    /// The very first structure is invalid: probably not this format at all.
    pub invalid_start: bool,
    pub notes: Vec<String>,
    pub damage: Vec<Damage>,
}
