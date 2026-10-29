use super::*;

fn hour(y: i64, m: i64, d: i64, h: i64) -> i64 {
    Timestamp::from_civil(y, m, d, h, 0, 0).unwrap().unix_secs() / 3600
}

fn row(kind: ActivityKind, at: i64, count: u64) -> ActivityRow {
    ActivityRow { volume: Some(1), path: "Users/a/NTUSER.DAT".into(), kind, hour: at, count }
}

fn window() -> UsageWindow {
    UsageWindow::until(Timestamp::from_civil(2015, 1, 1, 0, 0, 0).unwrap())
}

fn day(w: &Option<When>) -> String {
    w.map(|w| w.0.to_string()[..10].to_string()).unwrap_or_default()
}

/// Two seasons of evening use with a long break, a reset-clock stray in 2003 and one from
/// 2030 (after the image).
fn rows() -> Vec<ActivityRow> {
    let mut rows = Vec::new();
    for d in 1..=28 {
        rows.push(row(ActivityKind::Web, hour(2010, 3, d, 18), 20));
        rows.push(row(ActivityKind::Logon, hour(2010, 3, d, 17), 1));
    }
    for d in [2, 9, 16] {
        rows.push(row(ActivityKind::Program, hour(2011, 6, d, 19), 5));
        rows.push(row(ActivityKind::Wallet, hour(2011, 6, d, 20), 2));
    }
    rows.push(row(ActivityKind::Document, hour(2003, 1, 1, 0), 2));
    rows.push(row(ActivityKind::Web, hour(2030, 5, 5, 12), 400));
    rows.push(row(ActivityKind::Web, hour(1990, 5, 5, 12), 3));
    rows
}

#[test]
fn in_use_range_ignores_impossible_dates_and_strays() {
    let report = UsageAnalyzer::new(window(), None).analyze(&rows());
    assert_eq!(report.out_of_range, 403, "1990 and 2030 are outside the window");
    assert_eq!((day(&report.first_day), day(&report.last_day)), ("2010-03-01".into(), "2011-06-16".into()));
    assert_eq!(report.outliers.len(), 1);
    assert_eq!((report.outliers[0].from.0.to_string(), report.outliers[0].events), ("2003-01-01 00:00:00".into(), 2));
    assert_eq!(report.active_days, 31);
    assert_eq!(report.range_label().as_deref(), Some("2010-03-01 – 2011-06-16"));
}

#[test]
fn periods_split_on_long_gaps_and_explain_themselves() {
    let report = UsageAnalyzer::new(window(), None).analyze(&rows());
    assert_eq!(report.periods.len(), 2);
    let spring = &report.periods[0];
    assert_eq!((spring.active_days, spring.events, spring.span_days()), (28, 28 * 21, 28));
    assert_eq!((spring.kinds[0].kind, spring.kinds[0].events, spring.kinds[0].days), (ActivityKind::Web, 560, 28));
    let summer = &report.periods[1];
    assert_eq!((summer.from.0.to_string(), summer.active_days), ("2011-06-02 00:00:00".into(), 3));
    assert!(summer.kinds.iter().any(|k| k.kind == ActivityKind::Wallet && k.events == 6));
    assert_eq!(report.months.len(), 16, "March 2010 through June 2011, quiet months included");
    assert_eq!((report.months[0].active_days, report.months[1].active_days), (28, 0));
    assert!((report.days_per_month - 31.0 / 16.0).abs() < 1e-4);
}

#[test]
fn typical_hours_and_weekdays_follow_the_local_clock() {
    let utc = UsageAnalyzer::new(window(), None).analyze(&rows());
    assert_eq!(utc.typical_hours, Some((18, 19)), "most events are the 18:00 browsing");
    assert_eq!(utc.clock, "UTC");
    let moscow = UsageAnalyzer::new(window(), Some(-180)).analyze(&rows());
    assert_eq!(moscow.typical_hours, Some((21, 22)));
    assert_eq!(moscow.clock, "UTC+03:00");
    assert_eq!(moscow.weekdays.iter().sum::<u64>(), moscow.events);
    // 2011-06-02 was a Thursday.
    assert!(utc.weekdays[3] > 0);
}

#[test]
fn a_lone_short_session_stays_when_it_is_the_only_evidence() {
    let rows = vec![row(ActivityKind::Logon, hour(2009, 1, 5, 10), 1)];
    let report = UsageAnalyzer::new(window(), None).analyze(&rows);
    assert_eq!((report.periods.len(), report.outliers.len()), (1, 0));
    assert!(UsageAnalyzer::new(window(), None).analyze(&[]).is_empty());
}

#[test]
fn a_late_short_session_close_to_the_rest_is_real_use() {
    let mut rows = rows();
    rows.push(row(ActivityKind::Logon, hour(2011, 9, 1, 10), 1));
    let report = UsageAnalyzer::new(window(), None).analyze(&rows);
    assert_eq!(day(&report.last_day), "2011-09-01", "77 days after the last period is not a stray");
    assert_eq!(report.periods.len(), 3);
}

#[test]
fn typical_hours_wrap_past_midnight() {
    let mut hours = [0u64; 24];
    hours[23] = 10;
    hours[0] = 10;
    hours[1] = 10;
    hours[12] = 1;
    assert_eq!(typical_hours(&hours), Some((23, 2)));
    assert_eq!(typical_hours(&[0; 24]), None);
}
