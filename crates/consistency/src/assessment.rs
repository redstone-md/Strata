//! Runs every check over one disk and weighs their bearings into a verdict: unreadable beats
//! wiped, wiped beats little use, and a disk nothing was read from yet is not judged.

use crate::checks;
use crate::inputs::DiskInputs;
use crate::observation::{Assessment, Bearing, Observation, Verdict, VerdictKind};
use crate::units::day;

impl Assessment {
    pub fn of(disk: &DiskInputs) -> Self {
        let mut observations = Vec::new();
        for check in checks::ALL {
            check.observe(disk, &mut observations);
        }
        // Stable: within a severity, the order of the checks.
        observations.sort_by(|a, b| b.severity.cmp(&a.severity));
        Assessment { verdict: verdict(disk, &observations), observations }
    }
}

fn verdict(disk: &DiskInputs, observations: &[Observation]) -> Verdict {
    let bearings = || observations.iter().map(|o| o.bearing);
    let nothing_read = !disk.indexed && disk.activity.active_days == 0 && disk.volumes.iter().all(|v| v.entries() == 0);
    if nothing_read {
        return Verdict { kind: VerdictKind::NotAnalysed, headline: "Not analysed yet".into(), since: None };
    }
    if bearings().any(|b| b == Bearing::Unreadable) {
        return Verdict { kind: VerdictKind::Unreadable, headline: "Strata could not read the file system".into(), since: None };
    }
    let wiped: Vec<_> = bearings().filter_map(|b| if let Bearing::Wiped(at) = b { Some(at) } else { None }).collect();
    if !wiped.is_empty() {
        let since = wiped.into_iter().flatten().max();
        let headline = match since {
            Some(t) => format!("Probably wiped or reinstalled on {}", day(t)),
            None => "Probably wiped or reinstalled".to_string(),
        };
        return Verdict { kind: VerdictKind::WipedOrReinstalled, headline, since };
    }
    if bearings().any(|b| b == Bearing::LittleUse) {
        return Verdict { kind: VerdictKind::LittleUse, headline: "Little use".into(), since: None };
    }
    Verdict { kind: VerdictKind::NormallyUsed, headline: "Looks normally used".into(), since: None }
}
