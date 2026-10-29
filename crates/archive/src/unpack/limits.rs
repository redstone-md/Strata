//! Expansion limits: nesting depth, bytes per member and per top-level archive, compression
//! ratio (decompression bombs) and member count.

use crate::entry::ArchiveEntry;
use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpackLimits {
    /// Deepest member level: members of the top-level archive are depth 1.
    pub max_depth: usize,
    /// Bytes expanded from one top-level archive, all levels together.
    pub max_total: u64,
    /// Bytes kept per member.
    pub max_member: u64,
    /// Output allowed per input byte once a member is larger than `ratio_floor`.
    pub max_ratio: u64,
    /// Members up to this size are never ratio-limited (zero-filled files compress ~1000:1).
    pub ratio_floor: u64,
    /// Members visited per top-level archive, all levels together.
    pub max_members: usize,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_total: 4 << 30,
            max_member: 512 << 20,
            max_ratio: 250,
            ratio_floor: 64 << 20,
            max_members: 100_000,
        }
    }
}

/// What is left of one top-level archive's allowance.
pub(crate) struct Budget {
    limits: UnpackLimits,
    remaining: Cell<u64>,
    members: Cell<usize>,
}

impl Budget {
    pub fn new(limits: UnpackLimits) -> Self {
        Self { limits, remaining: Cell::new(limits.max_total), members: Cell::new(0) }
    }

    /// Byte limit for one member; `container_len` stands in when the member's packed size is
    /// unknown (single-stream compressors).
    pub fn member_limit(&self, e: &ArchiveEntry, container_len: u64) -> usize {
        let packed = e.packed.unwrap_or(container_len).max(1);
        let by_ratio = packed.saturating_mul(self.limits.max_ratio).max(self.limits.ratio_floor);
        let limit = self.limits.max_member.min(self.remaining.get()).min(by_ratio);
        usize::try_from(limit).unwrap_or(usize::MAX)
    }

    /// Count one member; `false` when the member cap is reached.
    pub fn admit(&self) -> bool {
        let n = self.members.get();
        self.members.set(n + 1);
        n < self.limits.max_members
    }

    pub fn spend(&self, bytes: u64) {
        self.remaining.set(self.remaining.get().saturating_sub(bytes));
    }

    pub fn can_descend(&self, member_depth: usize) -> bool {
        member_depth < self.limits.max_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_limits_only_large_members() {
        let b = Budget::new(UnpackLimits::default());
        let mut e = ArchiveEntry::new(0, "x");
        e.packed = Some(1000);
        assert_eq!(b.member_limit(&e, 0), 64 << 20);
        e.packed = Some(1 << 20);
        assert_eq!(b.member_limit(&e, 0), 250 << 20);
        e.packed = Some(100 << 20);
        assert_eq!(b.member_limit(&e, 0), 512 << 20);
        b.spend(4 << 30);
        assert_eq!(b.member_limit(&e, 0), 0);
    }
}
