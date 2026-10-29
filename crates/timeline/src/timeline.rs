use crate::stats::{day_of, day_secs};
use crate::{Burst, DateRange, EventKind, Granularity, HistogramBucket, TimelineEvent};
use std::collections::BTreeMap;
use strata_kernel::Timestamp;

/// Ordered collection of events with the queries a timeline UI needs.
#[derive(Debug, Clone, Default)]
pub struct Timeline {
    events: Vec<TimelineEvent>,
    sorted: bool,
}

impl Timeline {
    pub fn new() -> Self {
        Self { events: Vec::new(), sorted: true }
    }

    pub fn from_events(events: Vec<TimelineEvent>) -> Self {
        let mut t = Self { events, sorted: false };
        t.sort();
        t
    }

    pub fn push(&mut self, event: TimelineEvent) {
        self.sorted &= self.events.last().is_none_or(|last| last.at() <= event.at());
        self.events.push(event);
    }

    pub fn extend(&mut self, events: impl IntoIterator<Item = TimelineEvent>) {
        for e in events {
            self.push(e);
        }
    }

    /// Stable sort by time, then kind, so equal-time events keep a deterministic order.
    pub fn sort(&mut self) {
        if !self.sorted {
            self.events.sort_by(|a, b| a.at().cmp(&b.at()).then(a.kind().cmp(&b.kind())));
            self.sorted = true;
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<TimelineEvent> {
        self.events
    }

    /// First and last event time.
    pub fn span(&self) -> Option<(Timestamp, Timestamp)> {
        let min = self.events.iter().map(|e| e.at()).min()?;
        let max = self.events.iter().map(|e| e.at()).max()?;
        Some((min, max))
    }

    /// Events with `from <= at <= to`.
    pub fn in_range(&self, from: Timestamp, to: Timestamp) -> impl Iterator<Item = &TimelineEvent> {
        self.events.iter().filter(move |e| from <= e.at() && e.at() <= to)
    }

    pub fn of_kinds<'a>(&'a self, kinds: &'a [EventKind]) -> impl Iterator<Item = &'a TimelineEvent> {
        self.events.iter().filter(move |e| kinds.contains(&e.kind()))
    }

    /// Case-insensitive substring search over title, detail, path, actor and tags.
    pub fn search<'a>(&'a self, text: &str) -> impl Iterator<Item = &'a TimelineEvent> {
        let needle = text.to_lowercase();
        self.events.iter().filter(move |e| e.matches_text(&needle))
    }

    pub fn tagged<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a TimelineEvent> {
        self.events.iter().filter(move |e| e.has_tag(tag))
    }

    /// Non-empty buckets in ascending order.
    pub fn histogram(&self, granularity: Granularity) -> Vec<HistogramBucket> {
        let mut map: BTreeMap<i64, HistogramBucket> = BTreeMap::new();
        for e in &self.events {
            let start = granularity.bucket_start(e.at());
            let b = map.entry(start).or_insert(HistogramBucket { start, count: 0, crypto: 0, deleted: 0 });
            b.count += 1;
            b.crypto += usize::from(e.is_crypto());
            b.deleted += usize::from(e.source().deleted);
        }
        map.into_values().collect()
    }

    /// Per-day histogram (the default zoom level).
    pub fn per_day(&self) -> Vec<HistogramBucket> {
        self.histogram(Granularity::Day)
    }

    /// Days whose event count is at least `factor` × the median active day and at least
    /// `min_count`. Filesystem MACB events are excluded: mass installs and AV scans touch
    /// every file and would drown user activity.
    pub fn bursts_with(&self, factor: f32, min_count: usize) -> Vec<Burst> {
        let mut per_day: BTreeMap<i64, usize> = BTreeMap::new();
        for e in self.events.iter().filter(|e| !e.kind().is_filesystem()) {
            *per_day.entry(day_of(e.at())).or_default() += 1;
        }
        let mut counts: Vec<usize> = per_day.values().copied().collect();
        if counts.is_empty() {
            return Vec::new();
        }
        counts.sort_unstable();
        let median = counts[counts.len() / 2].max(1) as f32;
        per_day
            .into_iter()
            .filter_map(|(day, count)| {
                let ratio = count as f32 / median;
                (count >= min_count && ratio >= factor).then_some(Burst { day, count, ratio })
            })
            .collect()
    }

    /// Bursts with defaults tuned for a home PC: 5× median and at least 20 events.
    pub fn bursts(&self) -> Vec<Burst> {
        self.bursts_with(5.0, 20)
    }

    /// Date ranges covered by crypto-tagged events; events less than `gap_days` apart merge
    /// into one range.
    pub fn crypto_window_with(&self, gap_days: i64) -> Vec<DateRange> {
        let mut times: Vec<Timestamp> = self.events.iter().filter(|e| e.is_crypto()).map(|e| e.at()).collect();
        times.sort_unstable();
        let gap = gap_days.max(0).saturating_mul(day_secs());
        let mut out: Vec<DateRange> = Vec::new();
        for t in times {
            match out.last_mut() {
                Some(r) if t.unix_secs() - r.end.unix_secs() <= gap => {
                    r.end = t;
                    r.events += 1;
                }
                _ => out.push(DateRange { start: t, end: t, events: 1 }),
            }
        }
        out
    }

    /// Crypto activity windows, merging events within a week of each other.
    pub fn crypto_window(&self) -> Vec<DateRange> {
        self.crypto_window_with(7)
    }
}

impl FromIterator<TimelineEvent> for Timeline {
    fn from_iter<I: IntoIterator<Item = TimelineEvent>>(iter: I) -> Self {
        Self::from_events(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CRYPTO_TAG, EventSource};

    fn ev(secs: i64, kind: EventKind, title: &str) -> TimelineEvent {
        TimelineEvent::new(Timestamp::from_unix_secs(secs).unwrap(), kind, title, EventSource::new("test", "/x"))
    }

    const MAY_14_2011: i64 = 1_305_331_200;
    const DAY: i64 = 86_400;

    #[test]
    fn sort_filter_search() {
        let mut t = Timeline::new();
        t.push(ev(MAY_14_2011 + 50, EventKind::UrlVisited, "http://mail.ru"));
        t.push(ev(MAY_14_2011 + 10, EventKind::ProgramRun, "bitcoin.exe").with_tag(CRYPTO_TAG));
        t.sort();
        assert_eq!(t.events()[0].title(), "bitcoin.exe");
        assert_eq!(t.search("MAIL").count(), 1);
        assert_eq!(t.of_kinds(&[EventKind::ProgramRun]).count(), 1);
        let from = Timestamp::from_unix_secs(MAY_14_2011 + 20).unwrap();
        let to = Timestamp::from_unix_secs(MAY_14_2011 + 100).unwrap();
        assert_eq!(t.in_range(from, to).count(), 1);
        assert_eq!(t.tagged("CRYPTO").count(), 1);
        assert_eq!(t.span().unwrap().0.unix_secs(), MAY_14_2011 + 10);
    }

    #[test]
    fn histogram_and_bursts() {
        let mut events = Vec::new();
        for d in 0..10 {
            events.push(ev(MAY_14_2011 + d * DAY, EventKind::UrlVisited, "x"));
            events.push(ev(MAY_14_2011 + d * DAY + 5, EventKind::UrlVisited, "y"));
        }
        for i in 0..40 {
            events.push(ev(MAY_14_2011 + 3 * DAY + i, EventKind::Search, "burst"));
        }
        // Filesystem noise on another day must not form a burst.
        for i in 0..500 {
            events.push(ev(MAY_14_2011 + 5 * DAY + i, EventKind::FileAccessed, "f"));
        }
        let t = Timeline::from_events(events);
        let hist = t.per_day();
        assert_eq!(hist.len(), 10);
        assert_eq!(hist[3].count, 42);
        let bursts = t.bursts();
        assert_eq!(bursts.len(), 1);
        assert_eq!(bursts[0].day, MAY_14_2011 + 3 * DAY);
        assert!(bursts[0].ratio > 5.0);
    }

    #[test]
    fn crypto_windows_merge_by_gap() {
        let t: Timeline = [
            ev(MAY_14_2011, EventKind::UrlVisited, "a").with_tag(CRYPTO_TAG),
            ev(MAY_14_2011 + 3 * DAY, EventKind::UrlVisited, "b").with_tag(CRYPTO_TAG),
            ev(MAY_14_2011 + 200 * DAY, EventKind::WalletActivity, "c").with_tag(CRYPTO_TAG),
            ev(MAY_14_2011 + 201 * DAY, EventKind::UrlVisited, "plain"),
        ]
        .into_iter()
        .collect();
        let w = t.crypto_window();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].events, 2);
        assert_eq!(w[0].days(), 4);
        assert!(w[1].contains(Timestamp::from_unix_secs(MAY_14_2011 + 200 * DAY).unwrap()));
    }

    #[test]
    fn empty_timeline() {
        let t = Timeline::new();
        assert!(t.bursts().is_empty() && t.crypto_window().is_empty() && t.per_day().is_empty());
        assert!(t.span().is_none());
    }
}
