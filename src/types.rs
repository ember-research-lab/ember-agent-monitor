//! Core types shared across modules.
//!
//! Event schema and trust zones map directly to design/agent-monitor-spec.md
//! §3 (Data model). The schema discipline noted there is non-negotiable:
//! `tool_result` is structurally distinct from `user_prompt` even though
//! Anthropic's protocol delivers both as `role: user`. The disambiguation
//! happens at parse time (proto module), never downstream.

use std::fmt;

/// Trust zone classification for any byte sequence the monitor sees.
/// See spec §2 ("Trust boundaries"). Path normalization is substrate-required
/// and happens before zone tagging — any path-shaped value gets tilde-expanded
/// and resolved before this enum is assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustZone {
    /// Text the user typed directly (Anthropic role:user that is not a tool_result).
    UserInput,
    /// Files within the project working directory.
    WorkspaceLocal,
    /// Known-sensitive paths (~/.ssh, ~/.aws, ~/.gnupg, ~/.config/gh, ~/.netrc,
    /// ~/.docker/config.json, .env*, id_rsa, id_ed25519, credentials, plus
    /// user-extensible additions). See trust::sensitive.
    SensitiveLocal,
    /// Local files outside the workspace.
    ExternalLocal,
    /// Content returned from any tool that ingested external data
    /// (web fetches, MCP servers reading files, GitHub issue contents, etc.).
    /// Treated as adversarial — this is the zone that gates instruction-shape
    /// detections.
    UntrustedToolOutput,
    /// /tmp, /var/tmp. Low-stakes by default but watched.
    Ephemeral,
    /// Zone could not be determined. Fall back to most-restrictive policy.
    Unknown,
}

impl TrustZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustZone::UserInput => "user_input",
            TrustZone::WorkspaceLocal => "workspace_local",
            TrustZone::SensitiveLocal => "sensitive_local",
            TrustZone::ExternalLocal => "external_local",
            TrustZone::UntrustedToolOutput => "untrusted_tool_output",
            TrustZone::Ephemeral => "ephemeral",
            TrustZone::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<TrustZone> {
        Some(match s {
            "user_input" => TrustZone::UserInput,
            "workspace_local" => TrustZone::WorkspaceLocal,
            "sensitive_local" => TrustZone::SensitiveLocal,
            "external_local" => TrustZone::ExternalLocal,
            "untrusted_tool_output" => TrustZone::UntrustedToolOutput,
            "ephemeral" => TrustZone::Ephemeral,
            "unknown" => TrustZone::Unknown,
            _ => return None,
        })
    }

    /// Inverse-trust score in [0.0, 1.0]: higher means less trusted.
    /// Used by the detection layer (spec §4): score = pattern × source_trust_inverse × severity.
    pub fn inverse_trust(&self) -> f64 {
        match self {
            TrustZone::UserInput => 0.05,
            TrustZone::WorkspaceLocal => 0.20,
            TrustZone::Ephemeral => 0.40,
            TrustZone::ExternalLocal => 0.60,
            TrustZone::SensitiveLocal => 0.80,
            TrustZone::UntrustedToolOutput => 1.00,
            TrustZone::Unknown => 0.90,
        }
    }
}

impl fmt::Display for TrustZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Event kinds. Maps to spec §3 ("Event kinds") exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    SessionStart,
    McpRegistration,
    SkillLoad,
    HookRegistration,
    PluginInstall,
    UserPrompt,
    ModelText,
    ToolCall,
    ToolResult,
    SubagentInvocation,
    InterAgentMessage,
    ClassifierDecision,
    Finding,
    Intervention,
    SessionEnd,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::SessionStart => "session_start",
            EventKind::McpRegistration => "mcp_registration",
            EventKind::SkillLoad => "skill_load",
            EventKind::HookRegistration => "hook_registration",
            EventKind::PluginInstall => "plugin_install",
            EventKind::UserPrompt => "user_prompt",
            EventKind::ModelText => "model_text",
            EventKind::ToolCall => "tool_call",
            EventKind::ToolResult => "tool_result",
            EventKind::SubagentInvocation => "subagent_invocation",
            EventKind::InterAgentMessage => "inter_agent_message",
            EventKind::ClassifierDecision => "classifier_decision",
            EventKind::Finding => "finding",
            EventKind::Intervention => "intervention",
            EventKind::SessionEnd => "session_end",
        }
    }

    pub fn parse(s: &str) -> Option<EventKind> {
        Some(match s {
            "session_start" => EventKind::SessionStart,
            "mcp_registration" => EventKind::McpRegistration,
            "skill_load" => EventKind::SkillLoad,
            "hook_registration" => EventKind::HookRegistration,
            "plugin_install" => EventKind::PluginInstall,
            "user_prompt" => EventKind::UserPrompt,
            "model_text" => EventKind::ModelText,
            "tool_call" => EventKind::ToolCall,
            "tool_result" => EventKind::ToolResult,
            "subagent_invocation" => EventKind::SubagentInvocation,
            "inter_agent_message" => EventKind::InterAgentMessage,
            "classifier_decision" => EventKind::ClassifierDecision,
            "finding" => EventKind::Finding,
            "intervention" => EventKind::Intervention,
            "session_end" => EventKind::SessionEnd,
            _ => return None,
        })
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Capability classes. Each tool registered via MCP gets tagged with one or
/// more of these. See spec §3 ("Capability composition"). Toxic combinations
/// are computed on the union over the session's tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    FileRead,
    FileWrite,
    FileWriteViaFilter,
    ListDirectory,
    RepoInit,
    RepoRead,
    RepoWrite,
    CodeExecute,
    CredentialAccess,
    EmailSend,
    NetworkOut,
    ShellExec,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::FileRead => "file_read",
            Capability::FileWrite => "file_write",
            Capability::FileWriteViaFilter => "file_write_via_filter",
            Capability::ListDirectory => "list_directory",
            Capability::RepoInit => "repo_init",
            Capability::RepoRead => "repo_read",
            Capability::RepoWrite => "repo_write",
            Capability::CodeExecute => "code_execute",
            Capability::CredentialAccess => "credential_access",
            Capability::EmailSend => "email_send",
            Capability::NetworkOut => "network_out",
            Capability::ShellExec => "shell_exec",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Three intervention modes. Distinct semantics on each direction (forward
/// vs backward). Set once at proxy startup; not per-session. See spec §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterventionMode {
    /// Log finding only, no rewrite.
    Observe,
    /// Forward: inject system-prompt warning. Backward: strip dangerous
    /// tool_use, substitute refusal text.
    Warn,
    /// Forward: refuse to forward request. Backward: strip dangerous
    /// tool_use, substitute refusal text.
    Block,
}

impl InterventionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            InterventionMode::Observe => "observe",
            InterventionMode::Warn => "warn",
            InterventionMode::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<InterventionMode> {
        Some(match s {
            "observe" => InterventionMode::Observe,
            "warn" => InterventionMode::Warn,
            "block" => InterventionMode::Block,
            _ => return None,
        })
    }
}

/// Detection-fidelity status. Per spec §2 ("Detection-fidelity status"):
/// silent degradation of coverage is a documented failure mode; the user
/// sees this status in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidelityStatus {
    /// Both proxy and file-watcher observing.
    FullFidelity,
    /// File-watcher running, proxy missing or restarted.
    DegradedStaticOnly,
    /// Proxy running, file-watcher missed events.
    DegradedDynamicOnly,
    /// Neither observer producing data.
    Failed,
}

impl FidelityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FidelityStatus::FullFidelity => "full_fidelity",
            FidelityStatus::DegradedStaticOnly => "degraded_static_only",
            FidelityStatus::DegradedDynamicOnly => "degraded_dynamic_only",
            FidelityStatus::Failed => "failed",
        }
    }
}

/// Severity for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Coefficient used in detection scoring (spec §4 footnote).
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Low => 0.25,
            Severity::Medium => 0.50,
            Severity::High => 0.80,
            Severity::Critical => 1.00,
        }
    }
}

/// Configuration loaded at daemon startup. Per spec §5 ("Configuration scope"):
/// intervention mode is global, not per-session. State scope hierarchy
/// (user/project/session) handled separately in the store layer.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub proxy_port: u16,
    pub mode: InterventionMode,
    pub data_dir: std::path::PathBuf,
    pub watch_dir: std::path::PathBuf,
    /// Upstream base URL for Anthropic-protocol traffic
    /// (e.g. `https://api.anthropic.com`). Path is appended per request.
    pub upstream_anthropic: String,
    /// Upstream base URL for OpenAI-compatible traffic
    /// (e.g. `https://api.openai.com`, `https://api.x.ai`,
    /// `https://generativelanguage.googleapis.com/v1beta/openai`,
    /// `http://localhost:11434/v1` for Ollama). Path is appended per
    /// request.
    pub upstream_openai: String,
    /// Optional path to a hash-pinned integrity manifest. When set, the
    /// daemon spawns an integrity-check thread that emits
    /// `frozen_file_modification` findings on hash drift. See
    /// `integrity::Manifest` for the on-disk schema.
    pub integrity_manifest: Option<std::path::PathBuf>,
}

impl DaemonConfig {
    /// Resolve a `Protocol` to its configured upstream base URL.
    /// Centralised here so adding a new protocol means adding one
    /// match arm + one config field, not hunting for `format!` calls.
    pub fn upstream_for(&self, protocol: crate::proto::Protocol) -> &str {
        match protocol {
            crate::proto::Protocol::Anthropic => &self.upstream_anthropic,
            crate::proto::Protocol::OpenAI => &self.upstream_openai,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let data_dir = std::path::PathBuf::from(&home).join(".ember/agent-monitor");
        let watch_dir = std::path::PathBuf::from(&home).join(".claude/projects");
        Self {
            proxy_port: 9452,
            mode: InterventionMode::Observe,
            data_dir,
            watch_dir,
            upstream_anthropic: "https://api.anthropic.com".into(),
            upstream_openai: "https://api.openai.com".into(),
            integrity_manifest: None,
        }
    }
}
