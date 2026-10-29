//! How much the disk was used: no or little user activity where a system is installed, long
//! silent stretches, the last active day, and user profile folders left almost empty.

use super::Check;
use crate::inputs::{DiskInputs, ProfileFolder};
use crate::observation::{Bearing, Observation, Severity, Signal};
use crate::units::{bytes, count, day, days_between, month, span};

/// Fewer active days than this is little use.
const LITTLE_USE_DAYS: u32 = 30;
/// A silent stretch at least this long between periods of use is worth a word.
const LONG_GAP_DAYS: i64 = 365;
/// A profile with fewer live files than this was barely used or emptied.
const EMPTY_PROFILE_FILES: u64 = 20;
/// Profile folders that belong to the system, not to a person (lowercase).
const SYSTEM_PROFILES: &[&str] = &[
    "default",
    "default user",
    "defaultapppool",
    "public",
    "all users",
    "localservice",
    "networkservice",
    "local service",
    "network service",
    "systemprofile",
    "temp",
    "lost+found",
];
/// Profiles named per observation; the rest are counted.
const NAMED_PROFILES: usize = 5;

pub(crate) struct ActivityCheck;

impl Check for ActivityCheck {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>) {
        let a = &disk.activity;
        let has_system = disk.installations.iter().any(|i| !i.previous);
        match (a.first_day, a.last_day) {
            (Some(first), Some(last)) => {
                if a.active_days < LITTLE_USE_DAYS {
                    out.push(
                        Observation::new(
                            Severity::Notice,
                            Signal::LittleActivity,
                            format!("Little use: {} active days", a.active_days),
                            format!(
                                "User activity (logons, programs, browsing, documents) was found on only {} days between {} \
                                 and {}. A computer in regular use leaves hundreds; this one was used rarely, briefly, or its \
                                 traces were cleaned.",
                                a.active_days,
                                day(first),
                                day(last)
                            ),
                        )
                        .figure("Active days", a.active_days.to_string())
                        .figure("Events", count(a.events))
                        .bearing(Bearing::LittleUse),
                    );
                }
                if let Some(gap) = longest_gap(disk) {
                    out.push(gap);
                }
                out.push(
                    Observation::new(
                        Severity::Info,
                        Signal::LastActivity,
                        format!("Last user activity on {}", day(last)),
                        "The latest day with logons, program runs, browsing or documents. Later file times come from \
                         copying, updates or the examination, not from a person using the computer.",
                    )
                    .figure("First active day", day(first))
                    .figure("Last active day", day(last)),
                );
            }
            _ if has_system => out.push(
                Observation::new(
                    Severity::Warning,
                    Signal::NoActivity,
                    "No dated user activity",
                    "An operating system is installed, but no logons, program runs, browsing or documents were found. The \
                     system was never really used, its traces were cleaned, or the Artifacts step has not run yet.",
                )
                .bearing(Bearing::LittleUse),
            ),
            _ => {}
        }
        if has_system {
            empty_profiles(&disk.profiles, out);
        }
    }
}

fn longest_gap(disk: &DiskInputs) -> Option<Observation> {
    let (days, from, to) =
        disk.activity.periods.windows(2).map(|w| (days_between(w[0].to, w[1].from), w[0].to, w[1].from)).max_by_key(|g| g.0)?;
    (days >= LONG_GAP_DAYS).then(|| {
        Observation::new(
            Severity::Notice,
            Signal::ActivityGap,
            format!("No activity for {} ({} to {})", span(days), month(from), month(to)),
            "No user activity at all in this stretch. The disk was put away and used again later, or the traces of that \
             time were deleted (cleaning programs, a reinstall).",
        )
        .figure("From", day(from))
        .figure("To", day(to))
        .figure("Length", span(days))
    })
}

fn empty_profiles(profiles: &[ProfileFolder], out: &mut Vec<Observation>) {
    let people = profiles.iter().filter(|p| !SYSTEM_PROFILES.contains(&p.user.to_lowercase().as_str()));
    let empty: Vec<&ProfileFolder> = people.filter(|p| p.live.files < EMPTY_PROFILE_FILES).collect();
    if empty.is_empty() {
        return;
    }
    let names: Vec<String> =
        empty.iter().take(NAMED_PROFILES).map(|p| format!("{} ({} files, {})", p.user, p.live.files, bytes(p.live.bytes))).collect();
    let more = empty.len().saturating_sub(NAMED_PROFILES);
    let mut list = names.join(", ");
    if more > 0 {
        list.push_str(&format!(" and {more} more"));
    }
    let deleted: u64 = empty.iter().map(|p| p.deleted.files).sum();
    let mut text = format!(
        "User profile folders fill up with settings, caches and documents within days of use. These hold almost nothing: {list}."
    );
    if deleted > 0 {
        text.push_str(&format!(" {} deleted files remain in them: they were emptied.", count(deleted)));
    } else {
        text.push_str(" They were barely used, or emptied and overwritten.");
    }
    let mut o = Observation::new(
        Severity::Notice,
        Signal::EmptyProfile,
        if empty.len() == 1 { format!("User folder {} almost empty", empty[0].user) } else { format!("{} user folders almost empty", empty.len()) },
        text,
    )
    .figure("Profiles", empty.len().to_string())
    .figure("Deleted files in them", count(deleted));
    if let [only] = empty.as_slice() {
        o = o.on(only.volume);
    }
    out.push(o)
}
