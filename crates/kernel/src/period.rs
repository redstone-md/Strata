//! The period of interest: a case-wide date range (e.g. 2008–2013) that narrows what every
//! list shows. Either end may be open. Things without a date are not judged by it.

use crate::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Period {
    /// First moment inside the period.
    pub from: Option<Timestamp>,
    /// First moment after the period.
    pub to: Option<Timestamp>,
}

impl Period {
    pub const ALL: Period = Period { from: None, to: None };

    pub fn is_all(&self) -> bool {
        self.from.is_none() && self.to.is_none()
    }

    /// Parse the user's bounds: `YYYY`, `YYYY-MM` or `YYYY-MM-DD`; empty for an open end.
    /// The end covers the whole period it names (`2013` runs through 31 December 2013).
    pub fn parse(from: &str, to: &str) -> Option<Period> {
        let from = from.trim();
        let to = to.trim();
        let p = Period {
            from: if from.is_empty() { None } else { Some(Self::bound(from, false)?) },
            to: if to.is_empty() { None } else { Some(Self::bound(to, true)?) },
        };
        match (p.from, p.to) {
            (Some(a), Some(b)) if a >= b => None,
            _ => Some(p),
        }
    }

    fn bound(text: &str, end: bool) -> Option<Timestamp> {
        let parts: Vec<i64> = text.split('-').map(|p| p.trim().parse().ok()).collect::<Option<_>>()?;
        let (y, m, d, len) = match parts.as_slice() {
            [y] => (*y, 1, 1, 1),
            [y, m] => (*y, *m, 1, 2),
            [y, m, d] => (*y, *m, *d, 3),
            _ => return None,
        };
        if !(1970..=2100).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return None;
        }
        let start = Timestamp::from_civil(y, m, d, 0, 0, 0)?;
        if !end {
            return Some(start);
        }
        match len {
            1 => Timestamp::from_civil(y + 1, 1, 1, 0, 0, 0),
            2 if m == 12 => Timestamp::from_civil(y + 1, 1, 1, 0, 0, 0),
            2 => Timestamp::from_civil(y, m + 1, 1, 0, 0, 0),
            _ => Timestamp::from_unix_secs(start.unix_secs() + 86_400),
        }
    }

    pub fn contains(&self, t: Timestamp) -> bool {
        self.from.is_none_or(|f| t >= f) && self.to.is_none_or(|e| t < e)
    }

    /// Does the span `[first, last]` touch the period? An unknown end counts as open.
    pub fn overlaps(&self, first: Option<Timestamp>, last: Option<Timestamp>) -> bool {
        let last = last.or(first);
        let first = first.or(last);
        self.to.is_none_or(|e| first.is_none_or(|f| f < e)) && self.from.is_none_or(|s| last.is_none_or(|l| l >= s))
    }

    /// The narrower start of the two (a list's own day filter inside the period).
    pub fn later_start(&self, other: Option<Timestamp>) -> Option<Timestamp> {
        match (self.from, other) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// The narrower end of the two.
    pub fn earlier_end(&self, other: Option<Timestamp>) -> Option<Timestamp> {
        match (self.to, other) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// `2008 – 2013`, `from 2008`, `until 2013-06-30`, `All dates`.
    pub fn label(&self) -> String {
        let show = |t: Timestamp, end: bool| {
            let t = if end { Timestamp::from_unix_secs(t.unix_secs() - 1).unwrap_or(t) } else { t };
            let (y, m, d, ..) = t.civil();
            match (m, d, end) {
                (1, 1, false) | (12, 31, true) => y.to_string(),
                _ => format!("{y}-{m:02}-{d:02}"),
            }
        };
        match (self.from, self.to) {
            (None, None) => "All dates".into(),
            (Some(f), None) => format!("from {}", show(f, false)),
            (None, Some(e)) => format!("until {}", show(e, true)),
            (Some(f), Some(e)) => format!("{} – {}", show(f, false), show(e, true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i64, m: i64, d: i64) -> Timestamp {
        Timestamp::from_civil(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn years_cover_whole_years() {
        let p = Period::parse("2008", "2013").unwrap();
        assert_eq!((p.from, p.to), (Some(at(2008, 1, 1)), Some(at(2014, 1, 1))));
        assert!(p.contains(at(2013, 12, 31)));
        assert!(!p.contains(at(2014, 1, 1)));
        assert_eq!(p.label(), "2008 – 2013");
        assert_eq!(Period::parse("", "2013-06-30").unwrap().label(), "until 2013-06-30");
        assert_eq!(Period::parse("", "").unwrap(), Period::ALL);
        assert!(Period::parse("2014", "2008").is_none());
        assert!(Period::parse("last year", "").is_none());
    }

    #[test]
    fn spans_and_undated_things() {
        let p = Period::parse("2008", "2013").unwrap();
        assert!(p.overlaps(Some(at(2005, 1, 1)), Some(at(2009, 1, 1))));
        assert!(!p.overlaps(Some(at(2015, 1, 1)), Some(at(2016, 1, 1))));
        assert!(p.overlaps(None, None), "an undated thing is not judged");
        assert!(p.overlaps(Some(at(2010, 1, 1)), None));
        assert_eq!(p.later_start(Some(at(2012, 5, 1))), Some(at(2012, 5, 1)));
        assert_eq!(p.earlier_end(None), Some(at(2014, 1, 1)));
    }
}
