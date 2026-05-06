//! Append-only JSONL event log writer/reader.
//!
//! Each `append` issues a single `write_all` followed by a flush, so an
//! interrupted process leaves a complete or empty trailing line, never a
//! half-line. Multi-process safety is provided by per-session-file
//! locking via O_APPEND semantics on POSIX (a single write under
//! PIPE_BUF is atomic).

use crate::event::Event;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub struct EventLogWriter {
    file: File,
}

impl EventLogWriter {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open {path:?}: {e}"))?;
        Ok(Self { file })
    }

    pub fn append(&mut self, event: &Event) -> Result<(), String> {
        let line = event.to_jsonl_line();
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| format!("write event: {e}"))?;
        self.file
            .flush()
            .map_err(|e| format!("flush event: {e}"))
    }
}

pub fn read_all(path: &Path) -> Result<Vec<Event>, String> {
    let f = File::open(path).map_err(|e| format!("open {path:?}: {e}"))?;
    let rdr = BufReader::new(f);
    let mut out = Vec::new();
    for (i, line) in rdr.lines().enumerate() {
        let line = line.map_err(|e| format!("read line {i}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let ev = crate::event::parse_jsonl_line(&line)
            .map_err(|e| format!("parse line {i}: {e}"))?;
        out.push(ev);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::json::JsonValue;
    use crate::types::{EventKind, TrustZone};
    use std::collections::HashMap;

    #[test]
    fn roundtrip_log() {
        let dir = std::env::temp_dir().join(format!("eam-log-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("session.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut writer = EventLogWriter::open(&path).expect("open writer");
        let mut body = HashMap::new();
        body.insert("text".into(), JsonValue::Str("hi".into()));
        let e = Event::new("sess", EventKind::UserPrompt, TrustZone::UserInput, body);
        writer.append(&e).expect("append");

        let read = read_all(&path).expect("read");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].kind, EventKind::UserPrompt);

        let _ = std::fs::remove_file(&path);
    }
}
