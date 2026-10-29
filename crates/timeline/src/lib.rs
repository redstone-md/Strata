//! Timeline context: every dated trace (browser visit, registry MRU, file MACB time) as one
//! [`TimelineEvent`], collected in a [`Timeline`] that sorts, filters and summarises them
//! (per-day histogram, activity bursts, crypto activity windows).

mod event;
mod stats;
mod timeline;

pub use event::{EventKind, EventSource, TimelineEvent};
pub use stats::{Burst, DateRange, Granularity, HistogramBucket};
pub use timeline::Timeline;

/// Tag put on every event that touches cryptocurrency (service, keyword or wallet trace).
pub const CRYPTO_TAG: &str = "crypto";
