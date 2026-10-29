//! Wallet file parsers. Each takes a whole file's bytes and returns a best-effort
//! [`WalletReport`] with [`strata_kernel::Damage`] notes; none of them panic on input.

pub mod records;
