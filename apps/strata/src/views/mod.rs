//! One module per screen. Views read the shared [`crate::session::Session`] and never touch
//! anything below the workbench facade.

pub mod accounts;
pub mod correlation;
mod disk_row;
pub mod disks;
pub mod hits;
pub mod overview;
pub mod settings;
pub mod tasks;
pub mod timeline;
pub mod wallets;
