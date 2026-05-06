#!/usr/bin/env python3
"""Convert Claude Code session JSONL to Ember event log."""
import json
import sys
import hashlib
from pathlib import Path
from typing import Iterator


def content_hash(content) -> str:
    """SHA-256 of content for drift detection and audit."""
    if isinstance(content, (dict, list)):
        content = json.dumps(content, sort_keys=True)
    return hashlib.sha256(str(content).encode()).hexdigest()[:16]


SENSITIVE_PATHS = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.netrc",
    "~/.npmrc", "~/.docker/config.json",
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "credentials",
]


def trust_zone(path: str, cwd: str) -> str:
    """Tag a path with its trust zone."""
    p = path.replace("/Users/aaron", "~")
    for sensitive in SENSITIVE_PATHS:
        if sensitive in p:
            return "sensitive_local"
    if path.startswith(cwd):
        return "workspace"
    if path.startswith("/tmp") or path.startswith("/var/tmp"):
        return "ephemeral"
    return "external_local"


def emit_events(jsonl_path: Path) -> Iterator[dict]:
    """Process a session JSONL and emit Ember events."""
    session_id = None
    cwd = None
    static_mcp_servers = []

    for line_num, line in enumerate(jsonl_path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        rec = json.loads(line)

        if rec.get("type") == "system" and rec.get("subtype") == "init":
            session_id = rec["sessionId"]
            cwd = rec["cwd"]
            static_mcp_servers = rec.get("mcpServers", [])

            yield {
                "kind": "session_start",
                "session_id": session_id,
                "timestamp": rec["timestamp"],
                "model": rec["model"],
                "cwd": cwd,
                "git_branch": rec.get("gitBranch"),
            }

            # Static graph: register each MCP server and its tools as nodes.
            for server in static_mcp_servers:
                yield {
                    "kind": "mcp_registration",
                    "session_id": session_id,
                    "timestamp": rec["timestamp"],
                    "server_name": server["name"],
                    "tools": server["tools"],
                    "tools_hash": content_hash(server["tools"]),
                }

        elif rec.get("type") == "user":
            content = rec["message"]["content"]
            if isinstance(content, str):
                # Plain user prompt
                yield {
                    "kind": "user_prompt",
                    "session_id": session_id,
                    "uuid": rec["uuid"],
                    "parent_uuid": rec.get("parentUuid"),
                    "timestamp": rec["timestamp"],
                    "content_hash": content_hash(content),
                    "trust_zone": "user",
                    "preview": content[:200],
                }
            elif isinstance(content, list):
                # Tool result (synthetic user role per Anthropic protocol)
                for block in content:
                    if block.get("type") == "tool_result":
                        result_content = block.get("content", "")
                        # Result trust zone tracks the tool that produced it.
                        # In a real impl we'd correlate via tool_use_id; here
                        # we mark all tool results as untrusted until proven.
                        yield {
                            "kind": "tool_result",
                            "session_id": session_id,
                            "uuid": rec["uuid"],
                            "parent_uuid": rec.get("parentUuid"),
                            "timestamp": rec["timestamp"],
                            "tool_use_id": block["tool_use_id"],
                            "content_hash": content_hash(result_content),
                            "content_preview": str(result_content)[:300],
                            "trust_zone": "untrusted_tool_output",
                            "size": len(str(result_content)),
                        }

        elif rec.get("type") == "assistant":
            for block in rec["message"]["content"]:
                if block.get("type") == "text":
                    yield {
                        "kind": "model_text",
                        "session_id": session_id,
                        "uuid": rec["uuid"],
                        "parent_uuid": rec.get("parentUuid"),
                        "timestamp": rec["timestamp"],
                        "content_hash": content_hash(block["text"]),
                        "preview": block["text"][:200],
                    }
                elif block.get("type") == "tool_use":
                    tool_name = block["name"]
                    args = block.get("input", {})

                    # Compute trust zone for any path arguments.
                    arg_zones = {}
                    for k, v in args.items():
                        if isinstance(v, str) and ("/" in v or "~" in v):
                            arg_zones[k] = trust_zone(v, cwd or "")

                    yield {
                        "kind": "tool_call",
                        "session_id": session_id,
                        "uuid": rec["uuid"],
                        "parent_uuid": rec.get("parentUuid"),
                        "timestamp": rec["timestamp"],
                        "tool_use_id": block["id"],
                        "tool_name": tool_name,
                        "args": args,
                        "args_hash": content_hash(args),
                        "arg_zones": arg_zones,
                    }


if __name__ == "__main__":
    path = Path(sys.argv[1])
    for event in emit_events(path):
        print(json.dumps(event))
