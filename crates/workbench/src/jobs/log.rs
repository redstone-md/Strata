//! A small per-job ring of human-readable log lines ("unpacked 312 members from x.zip").

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Lines kept per job; older ones fall off.
const CAPACITY: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogLine {
    /// Unix seconds.
    pub at: i64,
    pub text: String,
}

#[derive(Default)]
pub(crate) struct JobLog {
    lines: Mutex<VecDeque<LogLine>>,
}

impl JobLog {
    pub fn push(&self, text: impl Into<String>) {
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let mut lines = self.lines.lock();
        if lines.len() == CAPACITY {
            lines.pop_front();
        }
        lines.push_back(LogLine { at, text: text.into() });
    }

    pub fn lines(&self) -> Vec<LogLine> {
        self.lines.lock().iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_newest_lines() {
        let log = JobLog::default();
        for i in 0..CAPACITY + 5 {
            log.push(format!("line {i}"));
        }
        let lines = log.lines();
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines[0].text, "line 5");
        assert_eq!(lines.last().unwrap().text, format!("line {}", CAPACITY + 4));
    }
}
