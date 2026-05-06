#!/usr/bin/env python3
"""Build execution graph from events and run v1 detections."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


# Capability classes for MCP tools. In production, this would be a
# maintained registry. For validation, hand-tagged.
CAPABILITY_CLASSES = {
    "mcp__filesystem__read_file": ["file_read"],
    "mcp__filesystem__write_file": ["file_write"],
    "mcp__filesystem__list_directory": ["file_read"],
    "mcp__git__git_init": ["repo_init", "file_write"],
    "mcp__git__git_status": ["repo_read"],
    "mcp__git__git_log": ["repo_read"],
    "mcp__git__git_diff": ["repo_read", "file_write_via_filter"],
    "mcp__git__git_checkout": ["repo_write", "file_write"],
}

# Toxic capability combinations. These trigger combined-capability risk
# at session start, before any dynamic events.
TOXIC_COMBINATIONS = [
    {
        "name": "git_init + filesystem_write = arbitrary_code_execution",
        "required": {"repo_init", "file_write"},
        "rationale": "git init in arbitrary path + write to .git/config = "
                     "shell exec via git filters (Cyata 2026 RCE chain)",
        "severity": "high",
    },
]

# Instruction-shape patterns that suggest tool output contains directives
# aimed at the model rather than user-facing content.
INSTRUCTION_PATTERNS = [
    (r"SYSTEM[_ ]NOTE", "system-prefixed instruction"),
    (r"the assistant must", "imperative addressed to assistant"),
    (r"you MUST", "uppercase imperative"),
    (r"<!--\s*SYSTEM", "comment-hidden system directive"),
    (r"important:\s*ignore", "ignore-previous pattern"),
    (r"<\|im_start\|>", "chat-template injection"),
]

# Argument-injection patterns: flag-shapes appearing in non-flag fields.
ARG_INJECTION_PATTERNS = [
    (r"--output[=\s]", "flag injection in argument value"),
    (r"--exec[=\s]", "exec flag injection"),
    (r";\s*(rm|curl|bash|sh)\s", "command chain injection"),
    (r"\$\(.*\)", "command substitution"),
    (r"`[^`]+`", "backtick command substitution"),
]


def build_graph(events: list) -> dict:
    """Construct static + dynamic graph from events."""
    graph = {
        "session_id": None,
        "model": None,
        "cwd": None,
        "static": {
            "mcp_servers": [],
            "tools": {},  # tool_name -> {"server", "capabilities"}
            "capability_set": set(),
            "toxic_combinations": [],
        },
        "dynamic": {
            "nodes": [],
            "edges": [],
        },
        "tool_call_index": {},  # tool_use_id -> tool_call event
    }

    for ev in events:
        if ev["kind"] == "session_start":
            graph["session_id"] = ev["session_id"]
            graph["model"] = ev["model"]
            graph["cwd"] = ev["cwd"]
        elif ev["kind"] == "mcp_registration":
            graph["static"]["mcp_servers"].append(ev["server_name"])
            for tool in ev["tools"]:
                full_name = f"mcp__{ev['server_name']}__{tool}"
                caps = CAPABILITY_CLASSES.get(full_name, ["unknown"])
                graph["static"]["tools"][full_name] = {
                    "server": ev["server_name"],
                    "capabilities": caps,
                }
                graph["static"]["capability_set"].update(caps)
        elif ev["kind"] == "tool_call":
            graph["dynamic"]["nodes"].append(ev)
            graph["tool_call_index"][ev["tool_use_id"]] = ev
        elif ev["kind"] in ("tool_result", "user_prompt", "model_text"):
            graph["dynamic"]["nodes"].append(ev)

    # Static-graph analysis: toxic combination detection.
    cap_set = graph["static"]["capability_set"]
    for tc in TOXIC_COMBINATIONS:
        if tc["required"].issubset(cap_set):
            graph["static"]["toxic_combinations"].append(tc)

    # Build causal edges from parent_uuid chains.
    nodes_by_uuid = {n["uuid"]: n for n in graph["dynamic"]["nodes"]
                     if "uuid" in n}
    for node in graph["dynamic"]["nodes"]:
        parent = node.get("parent_uuid")
        if parent and parent in nodes_by_uuid:
            graph["dynamic"]["edges"].append({
                "kind": "causal",
                "from": parent,
                "to": node["uuid"],
            })

    # Build data-flow edges: tool_result -> next assistant message
    # using the same tool_use_id as a tool_call's predecessor.
    for node in graph["dynamic"]["nodes"]:
        if node["kind"] == "tool_result":
            graph["dynamic"]["edges"].append({
                "kind": "data_flow",
                "from": node["uuid"],
                "to": "next_assistant_decision",
                "tool_use_id": node["tool_use_id"],
                "trust_zone_in": node["trust_zone"],
            })

    return graph


def run_detections(graph: dict) -> list:
    """Apply v1 rule-based detection layer."""
    findings = []

    # === Static detections (run at session start) ===

    for tc in graph["static"]["toxic_combinations"]:
        findings.append({
            "type": "toxic_capability_composition",
            "severity": tc["severity"],
            "session_id": graph["session_id"],
            "scope": "static",
            "detail": tc["name"],
            "rationale": tc["rationale"],
        })

    # === Dynamic detections (per-event) ===

    for node in graph["dynamic"]["nodes"]:
        # Trust-zone violation on tool call arguments.
        if node["kind"] == "tool_call":
            for arg_name, zone in node.get("arg_zones", {}).items():
                if zone == "sensitive_local":
                    findings.append({
                        "type": "sensitive_zone_access",
                        "severity": "high",
                        "session_id": graph["session_id"],
                        "scope": "dynamic",
                        "node_uuid": node["uuid"],
                        "tool": node["tool_name"],
                        "argument": arg_name,
                        "value": node["args"].get(arg_name),
                        "rationale": f"Tool call to {node['tool_name']} "
                                     f"references sensitive path via {arg_name}",
                    })

            # Argument injection patterns.
            for arg_name, val in node.get("args", {}).items():
                if not isinstance(val, str):
                    continue
                for pat, label in ARG_INJECTION_PATTERNS:
                    if re.search(pat, val):
                        findings.append({
                            "type": "argument_injection_pattern",
                            "severity": "high",
                            "session_id": graph["session_id"],
                            "scope": "dynamic",
                            "node_uuid": node["uuid"],
                            "tool": node["tool_name"],
                            "argument": arg_name,
                            "pattern": label,
                            "matched_value": val,
                        })

        # Instruction-shape patterns in tool results.
        if node["kind"] == "tool_result":
            content = node.get("content_preview", "")
            for pat, label in INSTRUCTION_PATTERNS:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append({
                        "type": "instruction_shape_in_tool_result",
                        "severity": "medium",
                        "session_id": graph["session_id"],
                        "scope": "dynamic",
                        "node_uuid": node["uuid"],
                        "tool_use_id": node["tool_use_id"],
                        "pattern": label,
                        "trust_zone": node["trust_zone"],
                        "rationale": "Untrusted tool output contains directive-shaped text",
                    })

    return findings


def summarize(graph: dict, findings: list) -> str:
    out = []
    out.append("=" * 60)
    out.append("EMBER AGENT MONITOR — END-TO-END VALIDATION")
    out.append("=" * 60)
    out.append(f"\nSession: {graph['session_id']}")
    out.append(f"Model:   {graph['model']}")
    out.append(f"Workdir: {graph['cwd']}")
    out.append(f"\nStatic graph:")
    out.append(f"  MCP servers: {graph['static']['mcp_servers']}")
    out.append(f"  Capability set: {sorted(graph['static']['capability_set'])}")
    out.append(f"  Toxic combinations detected: "
               f"{len(graph['static']['toxic_combinations'])}")
    out.append(f"\nDynamic graph:")
    out.append(f"  Nodes: {len(graph['dynamic']['nodes'])}")
    out.append(f"  Edges: {len(graph['dynamic']['edges'])}")
    node_kinds = defaultdict(int)
    for n in graph['dynamic']['nodes']:
        node_kinds[n['kind']] += 1
    out.append(f"  Node kinds: {dict(node_kinds)}")

    out.append("\n" + "=" * 60)
    out.append(f"FINDINGS ({len(findings)} total)")
    out.append("=" * 60)

    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f['severity']].append(f)

    for sev in ["high", "medium", "low"]:
        for f in by_severity.get(sev, []):
            out.append(f"\n[{sev.upper()}] {f['type']}")
            out.append(f"  Scope: {f['scope']}")
            if f.get('tool'):
                out.append(f"  Tool: {f['tool']}")
            if f.get('argument'):
                out.append(f"  Argument: {f['argument']} = "
                           f"{f.get('value', f.get('matched_value', ''))}")
            if f.get('pattern'):
                out.append(f"  Pattern: {f['pattern']}")
            if f.get('rationale'):
                out.append(f"  Why: {f['rationale']}")
            if f.get('detail'):
                out.append(f"  Detail: {f['detail']}")

    return "\n".join(out)


if __name__ == "__main__":
    events = [json.loads(l) for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
    graph = build_graph(events)
    findings = run_detections(graph)
    print(summarize(graph, findings))
    print()
    Path("findings.json").write_text(json.dumps(findings, indent=2))
    print(f"Findings written to findings.json")
