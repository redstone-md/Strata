//! Value types produced by [`crate::Timeline`] summaries.

use serde::{Deserialize, Serialize};
use strata_kernel::Timestamp;

const DAY_SECS: i64 = 86_400;

/// Histogram bucket width for a zoomable timeline view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Granularity {
    Hour,
    Day,
    Month,
    Year,
}

impl Granularity {
    /// Start of the bucket containing `ts`, as Unix seconds.
    pub fn bucket_start(self, ts: Timestamp) -> i64 {
        let secs = ts.unix_secs();
        match self {
            Self::Hour => secs - secs.rem_euclid(3600),
            Self::Day => secs - secs.rem_euclid(DAY_SECS),
            Self::Month | Self::Year => {
                let (_, _, day, h, mi, s) = ts.civil();
                let month_start = secs - i64::from(day - 1) * DAY_SECS - i64::from(h * 3600 + mi * 60 + s);
                if self == Self::Month {
                    return month_start;
                }
                // Walk back month by month to January (at most 11 steps).
                let mut start = month_start;
                for _ in 0..12 {
                    let Some(at) = Timestamp::from_unix_secs(start) else { break };
                    let Some(before) = Timestamp::from_unix_secs(start - DAY_SECS) else { break };
                    if at.civil().1 <= 1 {
                        break;
                    }
                    start = Self::Month.bucket_start(before);
                }
                start
            }
        }
    }
}

/// One histogram bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Bucket start, Unix seconds UTC.
    pub start: i64,
    pub count: usize,
    /// Events tagged `crypto` inside the bucket.
    pub crypto: usize,
    /// Events from deleted / recovered sources inside the bucket.
    pub deleted: usize,
}

/// A day with activity far above the timeline's typical day.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Burst {
    /// Day start, Unix seconds UTC.
    pub day: i64,
    pub count: usize,
    /// `count / median(active-day counts)`.
    pub ratio: f32,
}

/// Inclusive time range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateRange {
    pub start: Timestamp,
    pub end: Timestamp,
    /// Number of events that formed the range.
    pub events: usize,
}

impl DateRange {
    pub fn contains(&self, ts: Timestamp) -> bool {
        self.start <= ts && ts <= self.end
    }

    pub fn days(&self) -> i64 {
        (self.end.unix_secs() - self.start.unix_secs()) / DAY_SECS + 1
    }
}

pub(crate) fn day_of(ts: Timestamp) -> i64 {
    Granularity::Day.bucket_start(ts)
}

pub(crate) const fn day_secs() -> i64 {
    DAY_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: i64) -> Timestamp {
        Timestamp::from_unix_secs(s).unwrap()
    }

    #[test]
    fn buckets() {
        // 2011-05-14 17:36:09 UTC
        let t = ts(1_305_394_569);
        assert_eq!(Timestamp::from_unix_secs(Granularity::Day.bucket_start(t)).unwrap().to_string(), "2011-05-14 00:00:00");
        assert_eq!(Timestamp::from_unix_secs(Granularity::Hour.bucket_start(t)).unwrap().to_string(), "2011-05-14 17:00:00");
        assert_eq!(Timestamp::from_unix_secs(Granularity::Month.bucket_start(t)).unwrap().to_string(), "2011-05-01 00:00:00");
        assert_eq!(Timestamp::from_unix_secs(Granularity::Year.bucket_start(t)).unwrap().to_string(), "2011-01-01 00:00:00");
    }
}
