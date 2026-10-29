//! One module per screen. Views read the shared [`crate::session::Session`] and never touch
//! anything below the workbench facade.

pub mod accounts;
pub mod correlation;
pub mod dashboard;
pub mod evidence;
pub mod hits;
pub mod settings;
pub mod wallets;
