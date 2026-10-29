//! Shared shapes of tool output: errors as text for the model, paged lists, UTC times and
//! date bounds, bitcoin amounts.

use serde::Serialize;
use std::fmt::Display;
use strata_workbench::Timestamp;

/// A tool result: compact JSON on success, a sentence for the model on failure.
pub(crate) type Reply<T> = Result<T, String>;

pub(crate) fn fail(e: impl Display) -> String {
    e.to_string()
}

/// Rows per page when the caller does not say, and the most it may ask for.
#[derive(Clone, Copy)]
pub(crate) struct Paging {
    pub default: usize,
    pub max: usize,
}

impl Paging {
    pub const LIST: Paging = Paging { default: 50, max: 500 };
    pub const LONG: Paging = Paging { default: 100, max: 1000 };

    pub fn limit(self, asked: Option<usize>) -> usize {
        asked.unwrap_or(self.default).clamp(1, self.max)
    }
}

/// One page of a longer list. `next_offset` is set while more rows follow.
#[derive(Serialize)]
pub(crate) struct Page<T> {
    pub offset: usize,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub items: Vec<T>,
}

impl<T> Page<T> {
    /// A page from a query asked for `limit + 1` rows: the extra row only says more exist.
    pub fn probed(mut rows: Vec<T>, offset: usize, limit: usize) -> Self {
        let more = rows.len() > limit;
        rows.truncate(limit);
        Self { offset, count: rows.len(), total: None, next_offset: more.then_some(offset + limit), items: rows }
    }

    /// A page cut out of a complete list.
    pub fn slice(rows: Vec<T>, offset: usize, limit: usize) -> Self {
        let total = rows.len();
        let items: Vec<T> = rows.into_iter().skip(offset).take(limit).collect();
        let end = offset + items.len();
        Self { offset, count: items.len(), total: Some(total), next_offset: (end < total).then_some(end), items }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        let items = self.items.into_iter().map(f).collect();
        Page { offset: self.offset, count: self.count, total: self.total, next_offset: self.next_offset, items }
    }

    pub fn try_map<U>(self, f: impl FnMut(T) -> Reply<U>) -> Reply<Page<U>> {
        let items = self.items.into_iter().map(f).collect::<Reply<Vec<U>>>()?;
        Ok(Page { offset: self.offset, count: self.count, total: self.total, next_offset: self.next_offset, items })
    }
}

/// UTC time as `YYYY-MM-DD HH:MM:SS`.
pub(crate) fn time(t: Timestamp) -> String {
    t.to_string()
}

/// UTC time of Unix seconds, if plausible.
pub(crate) fn unix_time(secs: i64) -> Option<String> {
    Timestamp::from_unix_secs(secs).map(time)
}

/// Satoshi as a BTC amount with eight decimals.
pub(crate) fn btc(sat: u64) -> String {
    format!("{}.{:08}", sat / 100_000_000, sat % 100_000_000)
}

/// Which end of a period a date names.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Bound {
    /// The first moment of the period.
    Start,
    /// The first moment after the period (`to=2012` covers all of 2012).
    End,
}

/// Parse `YYYY`, `YYYY-MM`, `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` (also with `T`) as UTC.
pub(crate) fn parse_date(text: &str, bound: Bound) -> Reply<Timestamp> {
    let s = text.trim();
    let bad = || format!("cannot read date {text:?}; use YYYY, YYYY-MM, YYYY-MM-DD or YYYY-MM-DD HH:MM:SS");
    if s.len() > 10 {
        return Timestamp::parse_iso8601(s).ok_or_else(bad);
    }
    let parts: Vec<i64> = s.split('-').map(|p| p.parse::<i64>().map_err(|_| bad())).collect::<Reply<_>>()?;
    let (y, m, d) = match parts.as_slice() {
        [y] => (*y, 1, 1),
        [y, m] => (*y, *m, 1),
        [y, m, d] => (*y, *m, *d),
        _ => return Err(bad()),
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    let (y, m, d) = match (bound, parts.len()) {
        (Bound::Start, _) => (y, m, d),
        (Bound::End, 1) => (y + 1, 1, 1),
        (Bound::End, 2) if m == 12 => (y + 1, 1, 1),
        (Bound::End, 2) => (y, m + 1, 1),
        (Bound::End, _) => {
            let day = Timestamp::from_civil(y, m, d, 0, 0, 0).ok_or_else(bad)?;
            return Timestamp::from_unix_secs(day.unix_secs() + 86_400).ok_or_else(bad);
        }
    };
    Timestamp::from_civil(y, m, d, 0, 0, 0).ok_or_else(bad)
}

/// Optional date parameter.
pub(crate) fn date_param(text: Option<&str>, bound: Bound) -> Reply<Option<Timestamp>> {
    text.filter(|t| !t.trim().is_empty()).map(|t| parse_date(t, bound)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i64, m: i64, d: i64) -> Timestamp {
        Timestamp::from_civil(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn dates_name_periods() {
        assert_eq!(parse_date("2012", Bound::Start), Ok(at(2012, 1, 1)));
        assert_eq!(parse_date("2012", Bound::End), Ok(at(2013, 1, 1)));
        assert_eq!(parse_date("2012-12", Bound::End), Ok(at(2013, 1, 1)));
        assert_eq!(parse_date("2012-02-28", Bound::End), Ok(at(2012, 2, 29)));
        assert_eq!(parse_date("2012-02-28 10:00:00", Bound::End), Ok(Timestamp::from_civil(2012, 2, 28, 10, 0, 0).unwrap()));
        assert!(parse_date("yesterday", Bound::Start).is_err());
        assert!(parse_date("2012-13", Bound::Start).is_err());
    }

    #[test]
    fn pages() {
        let p = Page::probed(vec![1, 2, 3], 10, 2);
        assert_eq!((p.count, p.next_offset), (2, Some(12)));
        let p = Page::slice((0..5).collect(), 3, 10);
        assert_eq!((p.items, p.total, p.next_offset), (vec![3, 4], Some(5), None));
        assert_eq!(btc(150_000_001), "1.50000001");
    }
}
