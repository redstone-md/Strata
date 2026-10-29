//! Linux desktop artefacts: shell history, GNOME recent files, login records, wallet
//! data folders.

mod history;
mod recent;
mod wallet_dirs;
mod wtmp;

pub(crate) use history::ShellHistory;
pub(crate) use recent::RecentlyUsed;
pub(crate) use wallet_dirs::WalletDir;
pub(crate) use wtmp::Wtmp;
