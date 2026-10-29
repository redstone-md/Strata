//! When the file systems were made and the systems installed, against when the disk was in
//! use: user activity from before a format or an install date means the disk was reformatted
//! or the system reinstalled over older data. `Windows.old` is noted as an earlier system.

use super::Check;
use crate::inputs::{Activity, DiskInputs, Installation, VolumeInputs};
use crate::observation::{Bearing, Observation, Severity, Signal};
use crate::units::{DAY_SECS, count, day, days_between, share};
use strata_kernel::Timestamp;

/// Activity this close before a date still counts as after it (clocks, time zones, the
/// install itself).
const SLACK_DAYS: i64 = 30;
/// Earlier use counts with at least this many active days and this share of all of them.
const MIN_DAYS_BEFORE: u32 = 5;
const SHARE_BEFORE: f64 = 0.1;
/// Fewer active days than this after a reinstall: the disk was retired soon after.
const FEW_DAYS_AFTER: u32 = 10;
/// A format and an install this close are the same event (setup formats the volume).
const SAME_EVENT_DAYS: i64 = 2;

pub(crate) struct HistoryCheck;

impl Check for HistoryCheck {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>) {
        for inst in disk.installations.iter().filter(|i| !i.previous) {
            if let Some(at) = inst.installed {
                out.push(installed(inst, at, disk));
            }
        }
        for v in &disk.volumes {
            if let Some(at) = v.file_table.and_then(|t| t.created) {
                out.push(formatted(v, at, disk));
            }
            if v.previous_windows > 0 {
                out.push(
                    Observation::new(
                        Severity::Notice,
                        Signal::PreviousWindows,
                        format!("Volume {}: Windows.old holds an earlier Windows", v.index),
                        "An upgrade or reinstall moved the previous Windows into Windows.old. Its user folders and registry \
                         are older evidence worth reading; Machines lists it as a previous installation.",
                    )
                    .on(v.index)
                    .figure("Entries in Windows.old", count(v.previous_windows)),
                );
            }
        }
    }
}

/// Active days well before `t`, when they are enough to call it earlier use.
fn earlier_use(activity: &Activity, t: Timestamp) -> Option<u32> {
    let cut = Timestamp::from_unix_secs(t.unix_secs() - SLACK_DAYS * DAY_SECS)?;
    let before = activity.days_before(cut);
    (before >= MIN_DAYS_BEFORE && share(u64::from(before), u64::from(activity.active_days)) >= SHARE_BEFORE).then_some(before)
}

fn installed(inst: &Installation, at: Timestamp, disk: &DiskInputs) -> Observation {
    let activity = if inst.activity.active_days > 0 { &inst.activity } else { &disk.activity };
    let Some(before) = earlier_use(activity, at) else {
        let o = Observation::new(
            Severity::Info,
            Signal::InstalledOverActivity,
            format!("{} installed on {}", inst.label, day(at)),
            "The install date the system recorded. User activity starts after it, as expected.",
        )
        .figure("Install date", day(at));
        return on(o, inst.volume);
    };
    let moves = inst.date_moves_on_update();
    let after = activity.days_after(at);
    let first = activity.first_day.map(day).unwrap_or_default();
    let mut text = format!(
        "The system's install date is {}, but {before} of {} active days come from before it (from {first}). The system \
         was most likely reinstalled over an older one, whose files are now gone or only deleted.",
        day(at),
        activity.active_days
    );
    if after < FEW_DAYS_AFTER {
        text.push_str(&format!(" Only {after} active days follow the install: the disk was retired soon after."));
    }
    if moves {
        text.push_str(" Windows 10 and 11 also move this date on every feature update, so it may only be an update.");
    }
    let o = Observation::new(
        if moves { Severity::Notice } else { Severity::Warning },
        Signal::InstalledOverActivity,
        format!("{} installed on {}, after {before} days of earlier use", inst.label, day(at)),
        text,
    )
    .figure("Install date", day(at))
    .figure("Active days before", before.to_string())
    .figure("Active days after", after.to_string())
    .bearing(if moves { Bearing::None } else { Bearing::Wiped(Some(at)) });
    on(o, inst.volume)
}

fn on(o: Observation, volume: Option<u32>) -> Observation {
    match volume {
        Some(v) => o.on(v),
        None => o,
    }
}

fn formatted(v: &VolumeInputs, at: Timestamp, disk: &DiskInputs) -> Observation {
    let same_as_install = disk
        .installations
        .iter()
        .filter(|i| i.volume == Some(v.index))
        .filter_map(|i| i.installed)
        .any(|i| days_between(i, at).abs() <= SAME_EVENT_DAYS);
    let earlier = earlier_use(&disk.activity, at).filter(|_| !same_as_install);
    let Some(before) = earlier else {
        return Observation::new(
            Severity::Info,
            Signal::Formatted,
            format!("Volume {} formatted on {}", v.index, day(at)),
            "When its file system was created (the creation time of the MFT). Anything older on this volume was there \
             before a format.",
        )
        .on(v.index)
        .figure("Formatted", day(at));
    };
    Observation::new(
        Severity::Warning,
        Signal::Formatted,
        format!("Volume {} formatted on {}, after earlier use", v.index, day(at)),
        format!(
            "The file system of volume {} was created on {}, but {before} active days of user activity predate it. The \
             volume was reformatted over older data; what was there before survives only in free space.",
            v.index,
            day(at)
        ),
    )
    .on(v.index)
    .figure("Formatted", day(at))
    .figure("Active days before", before.to_string())
    .bearing(Bearing::Wiped(Some(at)))
}
