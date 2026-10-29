//! Getting data out: files and folders through their filesystem, carved files and archive
//! members behind findings. One writer, one log format.

mod exports;
mod files;
mod writer;

pub use exports::{Exportable, export};
pub use files::{FileRecovery, RecoverySummary, assess, state_word, volume_folder};
pub use writer::{Item, LOG_NAME, Recovered, RecoveryWriter, sanitize};

/// `1 item`, `12 items`.
pub(crate) fn count_label(n: usize) -> String {
    format!("{n} {}", if n == 1 { "item" } else { "items" })
}
