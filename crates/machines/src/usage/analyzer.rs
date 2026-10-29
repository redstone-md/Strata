//! Turns hourly activity counts into a [`UsageReport`].
//!
//! 1. Drop impossible dates (outside the [`UsageWindow`]).
//! 2. Bucket by local day when the machine's time zone is known.
//! 3. Cluster active days: a gap longer than [`UsageAnalyzer::GAP_DAYS`] starts a new period.
//! 4. Trim stray clusters at either end — at most [`UsageAnalyzer::STRAY_DAYS`] days and
//!    [`UsageAnalyzer::STRAY_EVENTS`] events, more than [`UsageAnalyzer::STRAY_GAP_DAYS`] from
//!    the rest (a reset CMOS clock, one mis-dated file) — and report them as outliers.

use super::{ActivityKind, ActivityRow, KindCount, MonthActivity, Outlier, Period, UsageReport, UsageWindow};
use crate::profile::utc_offset;
use crate::values::When;
use std::collections::BTreeMap;
use strata_kernel::Timestamp;

const KINDS: usize = ActivityKind::ALL.len();
/// Share of all activity the typical hours must hold.
const TYPICAL_SHARE: f64 = 0.7;

#[derive(Default, Clone)]
struct Day {
    events: u64,
    kinds: [u64; KINDS],
    hours: [u64; 24],
}

pub struct UsageAnalyzer {
    window: UsageWindow,
    /// Minutes to add to local time for UTC; `None` keeps UTC days.
    bias: Option<i32>,
}

impl UsageAnalyzer {
    /// Days without activity that split two periods.
    pub const GAP_DAYS: i64 = 30;
    /// A cluster this far from the rest may be a stray...
    pub const STRAY_GAP_DAYS: i64 = 180;
    /// ...when it is this small.
    pub const STRAY_DAYS: usize = 2;
    pub const STRAY_EVENTS: u64 = 10;

    pub fn new(window: UsageWindow, bias: Option<i32>) -> Self {
        Self { window, bias }
    }

    pub fn analyze<'r>(&self, rows: impl IntoIterator<Item = &'r ActivityRow>) -> UsageReport {
        let mut report = UsageReport { clock: self.bias.map_or_else(|| "UTC".to_string(), utc_offset), ..Default::default() };
        let mut days: BTreeMap<i64, Day> = BTreeMap::new();
        for row in rows {
            let Some(at) = row.at().filter(|t| self.window.contains(*t)) else {
                report.out_of_range += row.count;
                continue;
            };
            let local = at.unix_secs() - i64::from(self.bias.unwrap_or(0)) * 60;
            let day = days.entry(local.div_euclid(86_400)).or_default();
            day.events += row.count;
            day.kinds[row.kind.index()] += row.count;
            day.hours[(local.rem_euclid(86_400) / 3600) as usize] += row.count;
        }
        let mut clusters = cluster(&days);
        self.trim_strays(&mut clusters, &days, &mut report.outliers);
        report.periods = clusters.iter().filter_map(|c| period(c, &days)).collect();
        let kept: Vec<(i64, &Day)> = clusters.iter().flatten().filter_map(|d| days.get(d).map(|s| (*d, s))).collect();
        for (d, s) in &kept {
            report.active_days += 1;
            report.events += s.events;
            for (h, n) in s.hours.iter().enumerate() {
                report.hours[h] += n;
            }
            // 1970-01-01 was a Thursday; Monday is 0.
            report.weekdays[(d + 3).rem_euclid(7) as usize] += s.events;
        }
        report.first_day = kept.first().and_then(|(d, _)| day_stamp(*d));
        report.last_day = kept.last().and_then(|(d, _)| day_stamp(*d));
        report.months = months(&kept);
        report.days_per_month = if report.months.is_empty() { 0.0 } else { report.active_days as f32 / report.months.len() as f32 };
        report.typical_hours = typical_hours(&report.hours);
        report
    }

    fn trim_strays(&self, clusters: &mut Vec<Vec<i64>>, days: &BTreeMap<i64, Day>, outliers: &mut Vec<Outlier>) {
        let events = |c: &[i64]| c.iter().filter_map(|d| days.get(d)).map(|s| s.events).sum::<u64>();
        let tiny = |c: &[i64]| c.len() <= Self::STRAY_DAYS && events(c) <= Self::STRAY_EVENTS;
        let gap = |a: &[i64], b: &[i64]| match (a.last(), b.first()) {
            (Some(x), Some(y)) => y - x,
            _ => 0,
        };
        let mut strays = Vec::new();
        while clusters.len() > 1 && tiny(&clusters[0]) && gap(&clusters[0], &clusters[1]) > Self::STRAY_GAP_DAYS {
            strays.push(clusters.remove(0));
        }
        while clusters.len() > 1 {
            let n = clusters.len();
            if !(tiny(&clusters[n - 1]) && gap(&clusters[n - 2], &clusters[n - 1]) > Self::STRAY_GAP_DAYS) {
                break;
            }
            strays.extend(clusters.pop());
        }
        strays.sort();
        for c in strays {
            if let (Some(from), Some(to)) = (c.first().and_then(|d| day_stamp(*d)), c.last().and_then(|d| day_stamp(*d))) {
                outliers.push(Outlier { from, to, events: events(&c) });
            }
        }
    }
}

/// Runs of active days with no gap longer than [`UsageAnalyzer::GAP_DAYS`].
fn cluster(days: &BTreeMap<i64, Day>) -> Vec<Vec<i64>> {
    let mut out: Vec<Vec<i64>> = Vec::new();
    for &d in days.keys() {
        match out.last_mut() {
            Some(c) if c.last().is_some_and(|last| d - last <= UsageAnalyzer::GAP_DAYS) => c.push(d),
            _ => out.push(vec![d]),
        }
    }
    out
}

fn period(days_in: &[i64], days: &BTreeMap<i64, Day>) -> Option<Period> {
    let mut kinds = [(0u64, 0u32); KINDS];
    let mut events = 0;
    for s in days_in.iter().filter_map(|d| days.get(d)) {
        events += s.events;
        for (i, n) in s.kinds.iter().enumerate().filter(|(_, n)| **n > 0) {
            kinds[i].0 += n;
            kinds[i].1 += 1;
        }
    }
    let mut kinds: Vec<KindCount> =
        ActivityKind::ALL.iter().zip(kinds).filter(|(_, (n, _))| *n > 0).map(|(k, (events, days))| KindCount { kind: *k, events, days }).collect();
    kinds.sort_by_key(|k| std::cmp::Reverse(k.events));
    let (from, to) = (day_stamp(*days_in.first()?)?, day_stamp(*days_in.last()?)?);
    Some(Period { from, to, active_days: days_in.len() as u32, events, kinds })
}

fn day_stamp(day: i64) -> Option<When> {
    Timestamp::from_unix_secs(day.checked_mul(86_400)?).map(When)
}

/// Every month from the first to the last kept day.
fn months(kept: &[(i64, &Day)]) -> Vec<MonthActivity> {
    let month_of = |d: i64| day_stamp(d).map(|w| {
        let (y, m, ..) = w.0.civil();
        (y, m)
    });
    let (Some(first), Some(last)) = (kept.first().and_then(|(d, _)| month_of(*d)), kept.last().and_then(|(d, _)| month_of(*d))) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let (mut y, mut m) = first;
    while (y, m) <= last {
        out.push(MonthActivity { year: y, month: m, active_days: 0, events: 0 });
        (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    }
    for (d, s) in kept {
        if let Some((y, m)) = month_of(*d)
            && let Some(row) = out.iter_mut().find(|r| r.year == y && r.month == m)
        {
            row.active_days += 1;
            row.events += s.events;
        }
    }
    out
}

/// Shortest circular run of hours holding [`TYPICAL_SHARE`] of the activity.
fn typical_hours(hours: &[u64; 24]) -> Option<(u8, u8)> {
    let total: u64 = hours.iter().sum();
    if total == 0 {
        return None;
    }
    let need = (total as f64 * TYPICAL_SHARE).ceil() as u64;
    for len in 1..=24usize {
        let best = (0..24usize).map(|start| (start, (0..len).map(|i| hours[(start + i) % 24]).sum::<u64>())).max_by_key(|(start, sum)| (*sum, std::cmp::Reverse(*start)));
        if let Some((start, sum)) = best
            && sum >= need
        {
            return Some((start as u8, ((start + len) % 24) as u8));
        }
    }
    None
}

#[cfg(test)]
mod tests;
