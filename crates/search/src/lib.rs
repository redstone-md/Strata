//! Search context: find arbitrary content anywhere on a disk, deleted data included.
//!
//! A [`SearchQuery`] (text in several encodings, hex bytes or a regex) compiles to a
//! [`SearchMatcher`]; wrapped in a [`SearchDetector`] it runs through the single-pass scan
//! engine over whatever ranges the scope selects. [`Snippet`] renders the bytes around a match.

mod encoding;
mod matcher;
mod query;
mod snippet;
mod utf16;

pub use encoding::Encoding;
pub use matcher::{CONTEXT, DETECTOR_ID, MAX_REGEX_MATCH, SearchDetector, SearchMatcher};
pub use query::{Pattern, Scope, SearchQuery};
pub use snippet::Snippet;
