//! Real-client compatibility gate (#64, layer 1 + 2 capture).
//!
//! Runs the *installed* `claude -p` through the proxy to a mock Anthropic
//! upstream. A hand-written mock encodes what we believe Claude Code sends;
//! #58 (query string 404) and #60 (synthetic-200 JSON over SSE) both shipped
//! because that belief was wrong. Only the real client can catch the next
//! divergence. CI installs a pinned Claude Code and sets `CI=true`: a missing
//! binary there is a hard failure (see `cc_support::require_claude`).
//!
//! Findings (Claude Code 2.1.305, see FEAT-monitor-64): `-p` always sends
//! `stream:true` (also with `--output-format stream-json`); `ANTHROPIC_API_KEY`
//! gives `x-api-key`, `ANTHROPIC_AUTH_TOKEN` gives `authorization: Bearer`;
//! no login is needed when the mock answers.

mod cc_support;
use cc_support::*;
use ember_agent_monitor::types::InterventionMode;
use std::path::Path;

fn assert_claude_wire(seen: &Seen, auth: &Auth, model_prefix: &str) {
    assert_eq!(
        seen.request_line, "POST /v1/messages?beta=true HTTP/1.1",
        "upstream request line (query string must survive the proxy, #58)"
    );
    assert!(
        seen.header("anthropic-beta").is_some(),
        "anthropic-beta missing: {:?}",
        seen.headers
    );
    assert_eq!(
        seen.header("anthropic-version").as_deref(),
        Some("2023-06-01")
    );
    match auth {
        Auth::ApiKey => assert!(seen.header("x-api-key").is_some(), "{:?}", seen.headers),
        Auth::Bearer => assert!(
            seen.header("authorization")
                .map(|a| a.starts_with("Bearer "))
                .unwrap_or(false),
            "authorization missing: {:?}",
            seen.headers
        ),
    }
    assert!(
        seen.is_stream(),
        "claude -p is expected to stream; body head: {}",
        &seen.body[..seen.body.len().min(200)]
    );
    assert!(
        seen.body.contains(&format!("\"model\":\"{model_prefix}")),
        "model alias not resolved to {model_prefix}*"
    );
    // The proxy must not offer upstream compression it cannot relay (#60).
    let ae = seen.header("accept-encoding").unwrap_or_default();
    assert!(ae.is_empty(), "accept-encoding leaked upstream: {ae}");
}

fn e2e(tag: &str, auth: Auth, model: &str, prefix: &str, extra: &[&str], expect_json_events: bool) {
    let Some(_v) = require_claude(tag) else {
        return;
    };
    let up = spawn_upstream();
    let proxy = start_proxy(tag, InterventionMode::Observe, &up.url);
    let run = run_claude(
        tag,
        &proxy.base_url(),
        match auth {
            Auth::ApiKey => Auth::ApiKey,
            Auth::Bearer => Auth::Bearer,
        },
        model,
        extra,
    );
    run.assert_answered_ok(tag);
    if expect_json_events {
        assert!(
            run.stdout.contains("\"type\":\"result\""),
            "no result event: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("\"is_error\":false"),
            "result is_error: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("\"text\":\"ok\""),
            "assistant text ok missing: {}",
            run.stdout
        );
    } else {
        assert_eq!(
            run.stdout.trim(),
            "ok",
            "stdout: {}\nstderr: {}",
            run.stdout,
            run.stderr
        );
    }
    let seen = up.seen.lock().unwrap();
    assert!(
        !seen.is_empty(),
        "mock upstream saw no request: claude never reached it through the proxy"
    );
    assert_claude_wire(&seen[0], &auth, prefix);
}

#[test]
fn claude_p_opus_api_key_answers_ok_through_proxy() {
    e2e("opus-key", Auth::ApiKey, "opus", "claude-opus", &[], false);
}

#[test]
fn claude_p_fable_bearer_answers_ok_through_proxy() {
    e2e(
        "fable-bearer",
        Auth::Bearer,
        "fable",
        "claude-fable",
        &[],
        false,
    );
}

#[test]
fn claude_p_stream_json_answers_ok_through_proxy() {
    e2e(
        "stream-json",
        Auth::Bearer,
        "opus",
        "claude-opus",
        &["--output-format", "stream-json", "--verbose"],
        true,
    );
}

/// An upstream 400 must reach the client as a failure (#60: the forwarder once
/// turned every upstream status into a synthetic 200).
#[test]
fn claude_p_upstream_400_is_a_failure_not_a_fake_ok() {
    let Some(_v) = require_claude("400") else {
        return;
    };
    let up = spawn_upstream_status(400);
    let proxy = start_proxy("400", InterventionMode::Observe, &up.url);
    let run = run_claude("400", &proxy.base_url(), Auth::ApiKey, "opus", &[]);
    assert_ne!(
        run.code,
        Some(-9),
        "claude hung instead of failing fast\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert_ne!(
        run.code,
        Some(0),
        "400 upstream must fail the run\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert_ne!(run.stdout.trim(), "ok", "400 turned into a fake ok");
    assert!(
        format!("{}{}", run.stdout, run.stderr).contains(SENTINEL),
        "upstream error text not surfaced\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        !up.seen.lock().unwrap().is_empty(),
        "request never reached upstream"
    );
}

/// Refreshes `tests/fixtures/claude-code/<version>/` from the installed client
/// (`just capture-claude-code`). Ignored in normal runs.
#[test]
#[ignore = "run via `just capture-claude-code` to refresh the wire-capture fixture"]
fn capture_claude_code_fixture() {
    let version = require_claude("capture").expect("capture needs the claude binary");
    let up = spawn_upstream();
    // Direct to the mock: the capture is what the client sent, not what a proxy relayed.
    let run = run_claude("capture", &up.url, Auth::Bearer, "opus", &[]);
    run.assert_answered_ok("capture");
    let seen = up.seen.lock().unwrap();
    let s = seen.first().expect("mock saw nothing");
    let mut head = format!("{}\n", s.request_line);
    for h in &s.headers {
        let (name, value) = h.split_once(':').expect("header");
        let (lname, value) = (name.trim().to_ascii_lowercase(), value.trim());
        let value = match lname.as_str() {
            "host" | "content-length" | "connection" => continue,
            "authorization" => "Bearer REDACTED".to_string(),
            "x-api-key" => "REDACTED".to_string(),
            "x-claude-code-session-id" => "00000000-0000-0000-0000-000000000000".to_string(),
            _ => value.to_string(),
        };
        head.push_str(&format!("{lname}: {value}\n"));
    }
    let body = redact_body(&s.body);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claude-code")
        .join(version);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("request.head"), head).unwrap();
    std::fs::write(dir.join("request.body.json"), body).unwrap();
    eprintln!("[cc-gate] wrote fixture {}", dir.display());
}

/// Redact identifiers inside the body without a JSON parser: `device_id`,
/// `account_uuid`, `session_id` values and any scratch path under the temp dir.
fn redact_body(body: &str) -> String {
    let mut out = body.to_string();
    for key in ["device_id", "account_uuid", "session_id"] {
        // Inside metadata.user_id the value is a JSON string holding escaped JSON.
        let pat = format!("\\\"{key}\\\":\\\"");
        let mut from = 0;
        while let Some(i) = out[from..].find(&pat) {
            let start = from + i + pat.len();
            let end = start + out[start..].find("\\\"").unwrap_or(0);
            out.replace_range(start..end, "REDACTED");
            from = start + "REDACTED".len();
        }
    }
    let tmp = std::env::temp_dir().to_string_lossy().to_string();
    while let Some(i) = out.find(&tmp) {
        let end = i + out[i..]
            .find(|c: char| c == '"' || c == '\\' || c.is_whitespace())
            .unwrap_or(out.len() - i);
        out.replace_range(i..end, "/REDACTED/scratch");
    }
    out
}
