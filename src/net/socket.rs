//! Event-stream Unix socket for sibling tools to subscribe.
//!
//! Spec §6: while running, the monitor emits tool-call events to
//! `~/.ember/agent-monitor/events.sock`. The network tool subscribes and
//! correlates against observed network activity by timing and process
//! tree. Loose temporal coupling — both tools share wall-clock and
//! process tree, no direct state sharing.
//!
//! v1: opens the socket, accepts subscribers, broadcasts each event as a
//! single JSONL line. Best-effort delivery — a slow subscriber gets
//! disconnected rather than backpressuring the proxy. Connect errors are
//! logged but never propagated (the network tool may not be installed).

use crate::event::Event;
use crate::json::{to_json_string, JsonValue};
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;

/// How many recent `tool_use_id`s the dedupe remembers.
const DEDUPE_CAP: usize = 4096;

/// Which ingest path produced a broadcast event. Emitted as the additive
/// top-level `source` field (ember-network ignores fields it does not consume).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Proxy,
    Watcher,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Proxy => "proxy",
            Source::Watcher => "watcher",
        }
    }
}

/// Bounded FIFO set of recently broadcast tool_use_ids.
#[derive(Default)]
struct Recent {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Recent {
    /// True if `id` was not already present (and is now remembered).
    fn insert(&mut self, id: &str) -> bool {
        if !self.set.insert(id.to_string()) {
            return false;
        }
        self.order.push_back(id.to_string());
        if self.order.len() > DEDUPE_CAP {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

pub struct EventSocket {
    path: PathBuf,
    subscribers: Mutex<Vec<UnixStream>>,
    recent: Mutex<Recent>,
}

impl EventSocket {
    pub fn open(path: &Path) -> Result<std::sync::Arc<Self>, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
        // Replace any stale socket file from a prior crash.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).map_err(|e| format!("bind {path:?}: {e}"))?;
        let me = std::sync::Arc::new(Self {
            path: path.to_path_buf(),
            subscribers: Mutex::new(Vec::new()),
            recent: Mutex::new(Recent::default()),
        });
        let me2 = std::sync::Arc::clone(&me);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                me2.subscribers.lock().unwrap().push(stream);
            }
        });
        Ok(me)
    }

    /// Broadcast an event to all subscribers, tagged with its `source`. A
    /// `tool_call` whose `tool_use_id` was already broadcast (a session both
    /// proxied and watched) is skipped. Any subscriber whose write fails is
    /// dropped — they can reconnect.
    pub fn broadcast(&self, event: &Event, source: Source) {
        if let Some(JsonValue::Str(id)) = event.body.get("tool_use_id") {
            if !self.recent.lock().unwrap().insert(id) {
                return;
            }
        }
        let mut json = event.to_json();
        if let JsonValue::Object(top) = &mut json {
            top.push(("source".into(), JsonValue::Str(source.as_str().into())));
        }
        let mut line = to_json_string(&json);
        line.push('\n');
        let mut subs = self.subscribers.lock().unwrap();
        subs.retain_mut(|s| s.write_all(line.as_bytes()).is_ok());
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
