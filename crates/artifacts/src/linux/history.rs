//! bash / zsh history. bash writes `#<epoch>` lines before commands when HISTTIMEFORMAT is
//! set; zsh extended history uses `: <epoch>:<elapsed>;<command>`. Commands without a time
//! become undated facts so nothing is lost.

use crate::results::Recorder;
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

/// Commands kept from one history file (old disks can hold huge histories).
const MAX_COMMANDS: usize = 50_000;

pub(crate) struct ShellHistory;

impl ShellHistory {
    pub fn parse(data: &[u8], rec: &mut Recorder) {
        let text = String::from_utf8_lossy(data);
        let mut pending: Option<Timestamp> = None;
        for line in text.lines().take(MAX_COMMANDS * 2) {
            let line = line.trim_end();
            if let Some(epoch) = line.strip_prefix('#').and_then(|s| s.trim().parse::<i64>().ok()) {
                pending = Timestamp::from_unix_secs(epoch);
                continue;
            }
            let (at, command) = match Self::zsh(line) {
                Some((at, cmd)) => (at, cmd),
                None => (pending.take(), line),
            };
            if command.trim().is_empty() {
                continue;
            }
            rec.emit(at, EventKind::ProgramRun, command.trim(), "shell history");
        }
    }

    /// `: 1612345678:0;command`
    fn zsh(line: &str) -> Option<(Option<Timestamp>, &str)> {
        let rest = line.strip_prefix(": ")?;
        let (meta, command) = rest.split_once(';')?;
        let epoch = meta.split(':').next()?.trim().parse::<i64>().ok()?;
        Some((Timestamp::from_unix_secs(epoch), command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dated_and_undated_commands() {
        let mut rec = Recorder::new("linux.shell_history");
        ShellHistory::parse(b"ls\n#1367000000\nelectrum --offline\n: 1367000100:0;bitcoin-qt\n", &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 2);
        assert_eq!(out.events[0].title(), "electrum --offline");
        assert!(out.facts.iter().any(|f| f.value == "ls"));
    }
}
