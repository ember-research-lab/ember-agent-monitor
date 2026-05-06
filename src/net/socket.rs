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
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;

pub struct EventSocket {
    path: PathBuf,
    subscribers: Mutex<Vec<UnixStream>>,
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
        });
        let me2 = std::sync::Arc::clone(&me);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                me2.subscribers.lock().unwrap().push(stream);
            }
        });
        Ok(me)
    }

    /// Broadcast an event to all subscribers. Any subscriber whose write
    /// fails is dropped — they can reconnect.
    pub fn broadcast(&self, event: &Event) {
        let line = event.to_jsonl_line();
        let mut subs = self.subscribers.lock().unwrap();
        subs.retain_mut(|s| s.write_all(line.as_bytes()).is_ok());
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
