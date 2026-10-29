//! Non-resident data runs (mapping pairs).

use super::attr::NonResident;
use super::boot::NtfsBoot;
use crate::alloc::ExtentList;
use strata_kernel::bytes::{int_le_var, u8_at, uint_le_var};

const MAX_RUNS: usize = 1 << 16;

/// `len` clusters of the attribute starting at `vcn`, stored at `lcn` (`None` = sparse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Run {
    vcn: u64,
    lcn: Option<u64>,
    len: u64,
}

impl Run {
    pub(super) fn vcn(&self) -> u64 {
        self.vcn
    }

    pub(super) fn lcn(&self) -> Option<u64> {
        self.lcn
    }

    pub(super) fn len(&self) -> u64 {
        self.len
    }
}

/// Decode a mapping-pairs array. Returns the runs read so far and whether decoding ended at
/// the proper terminator (false = garbage or truncation, runs are partial).
pub(super) fn decode(data: &[u8], start_vcn: u64) -> (Vec<Run>, bool) {
    let mut runs = Vec::new();
    let (mut pos, mut vcn, mut lcn) = (0usize, start_vcn, 0i64);
    while runs.len() < MAX_RUNS {
        let Some(header) = u8_at(data, pos) else { return (runs, false) };
        if header == 0 {
            return (runs, true);
        }
        let (len_size, off_size) = (usize::from(header & 0x0F), usize::from(header >> 4));
        if len_size == 0 || len_size > 8 || off_size > 8 {
            return (runs, false);
        }
        let Some(len) = uint_le_var(data, pos + 1, len_size).filter(|l| *l > 0) else { return (runs, false) };
        let target = if off_size == 0 {
            None
        } else {
            let Some(delta) = int_le_var(data, pos + 1 + len_size, off_size) else { return (runs, false) };
            match lcn.checked_add(delta).filter(|l| *l >= 0) {
                Some(next) => lcn = next,
                None => return (runs, false),
            }
            Some(lcn as u64)
        };
        runs.push(Run { vcn, lcn: target, len });
        let Some(next_vcn) = vcn.checked_add(len) else { return (runs, false) };
        vcn = next_vcn;
        pos += 1 + len_size + off_size;
    }
    (runs, false)
}

/// Lay the runs of every instance of one attribute out as file extents. Runs pointing past
/// the volume end become holes; the returned count says how many there were.
pub(super) fn layout(instances: &[&NonResident], boot: &NtfsBoot, list: &mut ExtentList) -> usize {
    let cs = boot.cluster_size();
    let mut sorted: Vec<&Run> = instances.iter().flat_map(|n| n.runs()).collect();
    sorted.sort_by_key(|r| r.vcn());
    let mut outside = 0;
    for run in sorted {
        let len = run.len().saturating_mul(cs);
        let vol = match run.lcn() {
            Some(lcn) => {
                let off = boot.cluster_offset(lcn, run.len());
                outside += usize::from(off.is_none());
                off
            }
            None => None,
        };
        list.push_at(run.vcn().saturating_mul(cs), vol, len);
    }
    outside
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_signed_deltas_and_sparse() {
        // 0x10 clusters at 0x1000; sparse 4; 2 clusters at 0x1000 - 0x10.
        let data = [0x21, 0x10, 0x00, 0x10, 0x01, 0x04, 0x11, 0x02, 0xF0, 0x00];
        let (runs, clean) = decode(&data, 0);
        assert!(clean);
        assert_eq!(runs.len(), 3);
        assert_eq!((runs[0].vcn(), runs[0].lcn(), runs[0].len()), (0, Some(0x1000), 0x10));
        assert_eq!((runs[1].vcn(), runs[1].lcn()), (0x10, None));
        assert_eq!((runs[2].vcn(), runs[2].lcn(), runs[2].len()), (0x14, Some(0xFF0), 2));
    }

    #[test]
    fn garbage_runs_stop_cleanly() {
        assert!(!decode(&[0x21, 0x10], 0).1);
        assert!(!decode(&[0x11, 0x01, 0x80], 0).1, "negative LCN rejected");
        assert!(!decode(&[0x9F], 0).1);
        assert!(!decode(&[], 0).1);
        let noise = crate::testutil::noise(4096, 7);
        let _ = decode(&noise, u64::MAX - 3);
    }
}
