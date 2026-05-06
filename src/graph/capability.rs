//! Tool-name → capability classes mapping.
//!
//! Spec §3: capabilities are computed on the lattice, not the server
//! topology. Tagging a tool by name is necessarily heuristic; the source of
//! truth in v1 is a static table for known MCP server tools, with
//! user-extensible additions via config. Unknown tools default to a
//! conservative `[file_read, file_write, network_out]` so unfamiliar MCP
//! servers don't slip through capability checks.

use crate::types::Capability;

pub fn parse(s: &str) -> Option<Capability> {
    Some(match s {
        "file_read" => Capability::FileRead,
        "file_write" => Capability::FileWrite,
        "file_write_via_filter" => Capability::FileWriteViaFilter,
        "list_directory" => Capability::ListDirectory,
        "repo_init" => Capability::RepoInit,
        "repo_read" => Capability::RepoRead,
        "repo_write" => Capability::RepoWrite,
        "code_execute" => Capability::CodeExecute,
        "credential_access" => Capability::CredentialAccess,
        "email_send" => Capability::EmailSend,
        "network_out" => Capability::NetworkOut,
        "shell_exec" => Capability::ShellExec,
        _ => return None,
    })
}

/// Tag a tool name with the capability classes it provides.
///
/// This table is intentionally explicit. Adding a new MCP server requires
/// editing this list — that's a feature, not a bug. Implicit auto-tagging
/// from heuristic name parsing was considered and rejected: the cost of
/// a missed tag (no detection) is asymmetric with the cost of a false tag
/// (a noisy warning).
pub fn tag_tool(name: &str) -> Vec<Capability> {
    use Capability::*;
    let lower = name.to_lowercase();

    // mcp__<server>__<tool> shape — Claude Code convention.
    if let Some(rest) = lower.strip_prefix("mcp__") {
        if let Some((server, tool)) = rest.split_once("__") {
            return tag_mcp(server, tool);
        }
    }

    // Built-in Claude Code tools.
    match lower.as_str() {
        "read" | "read_file" => vec![FileRead],
        "write" | "write_file" => vec![FileWrite],
        "edit" | "edit_file" => vec![FileRead, FileWrite],
        "bash" => vec![ShellExec, CodeExecute, FileRead, FileWrite, NetworkOut],
        "webfetch" | "websearch" => vec![NetworkOut],
        "ls" | "glob" | "grep" | "list_directory" => vec![FileRead, ListDirectory],
        "task" => vec![CodeExecute, FileRead, FileWrite, NetworkOut],
        // Conservative catch-all: don't presume network egress for unknown
        // tools. False-tagging an unknown tool as network_out cascades
        // into spurious lethal_trifecta_reachability findings on every
        // session that registers an unfamiliar MCP server. Same fix as
        // persistent's capability tagger.
        _ => vec![FileRead, FileWrite],
    }
}

/// Tag a tool by (server, tool) pair. Use this when the registration event
/// gives you both — preferred over name-shape parsing because it's
/// authoritative.
pub fn tag_mcp_tool(server: &str, tool: &str) -> Vec<Capability> {
    tag_mcp(server, tool)
}

fn tag_mcp(server: &str, tool: &str) -> Vec<Capability> {
    use Capability::*;
    match server {
        "git" => match tool {
            "git_init" => vec![RepoInit, FileWrite, FileWriteViaFilter],
            "git_status" | "git_log" | "git_diff" | "git_show" => vec![RepoRead, FileRead],
            "git_add" | "git_commit" | "git_branch" | "git_checkout" => vec![RepoWrite, FileWrite],
            "git_push" | "git_pull" | "git_clone" | "git_fetch" => {
                vec![RepoWrite, NetworkOut, FileWrite]
            }
            _ => vec![RepoRead, RepoWrite, FileRead, FileWrite],
        },
        "filesystem" => match tool {
            "read_file" | "list_directory" => vec![FileRead, ListDirectory],
            "write_file" | "edit_file" => vec![FileRead, FileWrite],
            "create_directory" | "delete_file" | "move_file" => vec![FileWrite],
            _ => vec![FileRead, FileWrite, ListDirectory],
        },
        "github" => match tool {
            "create_issue" | "create_pull_request" | "create_repo" => vec![NetworkOut, RepoWrite],
            "get_issue" | "get_pull_request" | "list_issues" | "search_code" => vec![NetworkOut],
            _ => vec![NetworkOut, RepoRead, RepoWrite],
        },
        "postmark" | "smtp" | "sendgrid" => vec![EmailSend, NetworkOut],
        "shell" | "bash" => vec![ShellExec, CodeExecute, FileRead, FileWrite],
        // Unknown MCP server: presume FileRead+FileWrite, NOT network. New
        // MCP servers must be added to this table by name to be flagged
        // as network-egress; the alternative (presume network) cascades
        // into spurious lethal_trifecta_reachability findings on every
        // unfamiliar server.
        _ => vec![FileRead, FileWrite],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyata_chain_caps() {
        let caps = tag_tool("mcp__git__git_init");
        assert!(caps.contains(&Capability::RepoInit));
        assert!(caps.contains(&Capability::FileWrite));
        assert!(caps.contains(&Capability::FileWriteViaFilter));

        let caps2 = tag_tool("mcp__filesystem__write_file");
        assert!(caps2.contains(&Capability::FileWrite));
    }
}
