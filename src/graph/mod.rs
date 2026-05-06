//! Static + dynamic execution graph.
//!
//! Spec §3 ("Graph construction"):
//!   - Static graph: built at session start from mcp_registration, skill_load,
//!     hook_registration, plugin_install events. Captures pre-execution surface.
//!   - Dynamic graph: built as the session runs. Nodes are events; edges are
//!     causal (parent_event_id) or trust-cross.
//!
//! Capability composition (spec §3): tool tags are in `capability::tag_tool`.

pub mod capability;

use crate::event::Event;
use crate::types::{Capability, EventKind};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Static graph: tools the agent can use, before any execution.
#[derive(Debug, Default, Clone)]
pub struct StaticGraph {
    /// MCP server name → declared tool list.
    pub mcp_servers: HashMap<String, Vec<String>>,
    /// All registered tool names (across MCP servers + built-ins).
    pub tools: BTreeSet<String>,
    /// Activated skills.
    pub skills: BTreeSet<String>,
    /// Configured hooks (event → list of handler descriptions).
    pub hooks: HashMap<String, Vec<String>>,
    /// Installed plugin bundles.
    pub plugins: BTreeSet<String>,
    /// Session capability set (union over all tools).
    pub capabilities: BTreeSet<String>,
}

impl StaticGraph {
    pub fn ingest(&mut self, ev: &Event) {
        match ev.kind {
            EventKind::McpRegistration => {
                let server = string_body(ev, "server").unwrap_or_default();
                let tools = list_body(ev, "tools");
                for t in &tools {
                    self.tools.insert(t.clone());
                    for cap in capability::tag_mcp_tool(&server, t) {
                        self.capabilities.insert(cap.as_str().into());
                    }
                }
                self.mcp_servers.insert(server, tools);
            }
            EventKind::SkillLoad => {
                if let Some(name) = string_body(ev, "name") {
                    self.skills.insert(name);
                }
            }
            EventKind::HookRegistration => {
                let event_kind = string_body(ev, "hook_event").unwrap_or_default();
                let handler = string_body(ev, "handler").unwrap_or_default();
                self.hooks.entry(event_kind).or_default().push(handler);
            }
            EventKind::PluginInstall => {
                if let Some(name) = string_body(ev, "name") {
                    self.plugins.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// Dynamic graph: causal chain of in-session events.
#[derive(Debug, Default, Clone)]
pub struct DynamicGraph {
    pub events: Vec<Event>,
    /// child event_id → parent event_id (when set).
    pub parent_edges: HashMap<String, String>,
    /// kind → count, for fast structural queries.
    pub kind_counts: HashMap<EventKind, usize>,
}

impl DynamicGraph {
    pub fn ingest(&mut self, ev: Event) {
        if let Some(parent) = &ev.parent_event_id {
            self.parent_edges
                .insert(ev.event_id.clone(), parent.clone());
        }
        *self.kind_counts.entry(ev.kind).or_insert(0) += 1;
        self.events.push(ev);
    }

    pub fn last_n(&self, n: usize) -> &[Event] {
        let len = self.events.len();
        let start = len.saturating_sub(n);
        &self.events[start..]
    }

    pub fn ancestors(&self, event_id: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut cur = self.parent_edges.get(event_id).cloned();
        while let Some(p) = cur {
            if !seen.insert(p.clone()) {
                break; // cycle guard
            }
            cur = self.parent_edges.get(&p).cloned();
            out.push(p);
        }
        out
    }
}

/// Combined session graph that the detection layer queries.
#[derive(Debug, Default, Clone)]
pub struct SessionGraph {
    pub static_graph: StaticGraph,
    pub dynamic_graph: DynamicGraph,
}

impl SessionGraph {
    pub fn ingest(&mut self, ev: Event) {
        self.static_graph.ingest(&ev);
        self.dynamic_graph.ingest(ev);
    }

    pub fn capability_set(&self) -> BTreeSet<Capability> {
        self.static_graph
            .capabilities
            .iter()
            .filter_map(|s| capability::parse(s))
            .collect()
    }
}

fn string_body(ev: &Event, key: &str) -> Option<String> {
    ev.body
        .get(key)
        .and_then(|v| match v {
            crate::json::JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}

fn list_body(ev: &Event, key: &str) -> Vec<String> {
    match ev.body.get(key) {
        Some(crate::json::JsonValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| match v {
                crate::json::JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
