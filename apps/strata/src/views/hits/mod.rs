//! Hit lists: one generic delegate and browser, configured per screen.

mod browser;
mod columns;
mod delegate;
mod detail;
mod detail_tree;
mod details;

pub use browser::{BrowserConfig, HitBrowser};
pub use columns::HitColumn;
