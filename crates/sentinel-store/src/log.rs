use anyhow::{Context, Result};
use sentinel_events::Event;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Append-only JSONL event log. This file is the source of truth; the SQLite
/// index is a derived cache that can be thrown away and rebuilt at any time.
pub struct EventLog {
    path: PathBuf,
    file: File,
}

impl EventLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        Ok(EventLog { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, ev: &Event) -> Result<()> {
        let mut line = serde_json::to_string(ev)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        Ok(())
    }

    pub fn len_bytes(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Reads whole lines starting at `offset`, returning the events and the
    /// offset just past the last complete line. A torn final line is left for
    /// the next call rather than being parsed.
    pub fn read_from(&self, offset: u64) -> Result<(Vec<Event>, u64)> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(f);
        let mut events = Vec::new();
        let mut consumed = offset;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = reader.read_line(&mut buf)?;
            if n == 0 || !buf.ends_with('\n') {
                break;
            }
            consumed += n as u64;
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line) {
                Ok(ev) => events.push(ev),
                Err(e) => eprintln!("sentinel: skipping malformed log line at {consumed}: {e}"),
            }
        }
        Ok((events, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_events::{run_id, EventKind};

    #[test]
    fn appends_and_reads_back_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = EventLog::open(tmp.path().join("events.jsonl")).unwrap();
        let run = run_id("/r", "s");
        for step in 1..=3 {
            log.append(&Event::new(run, step, EventKind::ToolCall).tool("bash"))
                .unwrap();
        }
        let (events, off) = log.read_from(0).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events.iter().map(|e| e.step).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(off, log.len_bytes().unwrap());

        let (tail, _) = log.read_from(off).unwrap();
        assert!(tail.is_empty(), "reading from the end yields nothing");
    }

    #[test]
    fn incremental_read_only_returns_new_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = EventLog::open(tmp.path().join("events.jsonl")).unwrap();
        let run = run_id("/r", "s");
        log.append(&Event::new(run, 1, EventKind::ToolCall))
            .unwrap();
        let (_, off) = log.read_from(0).unwrap();
        log.append(&Event::new(run, 2, EventKind::ToolResult))
            .unwrap();
        let (new, _) = log.read_from(off).unwrap();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].step, 2);
    }

    #[test]
    fn torn_trailing_line_is_not_consumed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events.jsonl");
        let mut log = EventLog::open(&path).unwrap();
        log.append(&Event::new(run_id("/r", "s"), 1, EventKind::ToolCall))
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial\":")
            .unwrap();
        let (events, off) = log.read_from(0).unwrap();
        assert_eq!(events.len(), 1);
        assert!(off < log.len_bytes().unwrap());
    }
}
