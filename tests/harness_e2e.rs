//! Real-client compatibility gate for the other harnesses (#64 scope add):
//! Codex CLI (OpenAI Responses API via `/openai/v1`), OpenCode and Pi (Anthropic
//! provider via `/v1/messages`). Same contract as `claude_code_e2e.rs`: the
//! *installed* binary runs through the in-process proxy to a mock upstream with
//! a scrubbed environment; CI installs pinned versions and `CI=true` turns a
//! missing binary into a failure (see `cc_support::require_harness`).
//!
//! Findings (Codex 0.163.0, OpenCode 1.19.3, Pi 0.73.1): Codex posts
//! `stream:true` to `<base>/responses` with `authorization: Bearer`; OpenCode and
//! Pi post `stream:true` to `<base>/v1/messages` with `x-api-key`; OpenCode also
//! fires a separate small-model title request per run.

mod cc_support;
use cc_support::*;
use ember_agent_monitor::types::InterventionMode;

const CODEX: Harness = Harness {
    name: "codex",
    bin: "codex",
    pinned: "0.163.0",
};
const OPENCODE: Harness = Harness {
    name: "opencode",
    bin: "opencode",
    pinned: "1.19.3",
};
const PI: Harness = Harness {
    name: "pi",
    bin: "pi",
    pinned: "0.73.1",
};

const PROMPT: &str = "reply with the single word ok";

fn run_codex(tag: &str, base: &str) -> ClaudeRun {
    let cfg = format!(
        "model = \"gpt-5\"\nmodel_provider = \"mock\"\n[model_providers.mock]\nname = \"mock\"\n\
         base_url = \"{base}/openai/v1\"\nenv_key = \"MOCK_KEY\"\nwire_api = \"responses\"\n"
    );
    run_harness(
        &CODEX,
        tag,
        &["exec", "--skip-git-repo-check", PROMPT],
        &[("CODEX_HOME", "{HOME}/codex"), ("MOCK_KEY", "dummy")],
        &[("codex/config.toml", &cfg)],
    )
}

fn run_pi(tag: &str, base: &str) -> ClaudeRun {
    let cfg = format!("{{\"providers\":{{\"anthropic\":{{\"baseUrl\":\"{base}\"}}}}}}");
    run_harness(
        &PI,
        tag,
        &[
            "-p",
            PROMPT,
            "--provider",
            "anthropic",
            "--model",
            "claude-opus-4-5",
        ],
        &[
            ("PI_CODING_AGENT_DIR", "{HOME}/pi"),
            ("ANTHROPIC_API_KEY", "sk-ant-dummy-for-cc-gate"),
        ],
        &[("pi/models.json", &cfg)],
    )
}

fn run_opencode(tag: &str, base: &str) -> ClaudeRun {
    let cfg = format!(
        "{{\"autoupdate\":false,\"share\":\"disabled\",\"provider\":{{\"anthropic\":{{\"options\":\
         {{\"baseURL\":\"{base}/v1\",\"apiKey\":\"sk-ant-dummy-for-cc-gate\"}}}}}}}}"
    );
    run_harness(
        &OPENCODE,
        tag,
        &["run", "-m", "anthropic/claude-opus-4-5", PROMPT],
        &[
            ("XDG_CONFIG_HOME", "{HOME}/xdg/config"),
            ("XDG_DATA_HOME", "{HOME}/xdg/data"),
            ("XDG_CACHE_HOME", "{HOME}/xdg/cache"),
            ("XDG_STATE_HOME", "{HOME}/xdg/state"),
        ],
        &[("cwd/opencode.json", &cfg)],
    )
}

fn answered_ok(run: &ClaudeRun, what: &str) {
    assert_eq!(
        run.code,
        Some(0),
        "{what}: exit code\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    // stdout is decorated by Codex/OpenCode (banner, ANSI); the reply is the last word.
    assert!(
        run.stdout.contains("ok"),
        "{what}: no `ok` in stdout\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
}

fn failed_not_fake_ok(run: &ClaudeRun, what: &str) {
    assert_ne!(
        run.code,
        Some(-9),
        "{what}: hung instead of failing fast\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert_ne!(
        run.code,
        Some(0),
        "{what}: upstream 400 must fail the run\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
}

fn anthropic_wire(seen: &[Seen], model: &str) {
    let s = seen
        .iter()
        .find(|s| s.body.contains(&format!("\"model\":\"{model}\"")))
        .unwrap_or_else(|| panic!("no request for model {model}: {seen:?}"));
    assert!(
        s.request_line.starts_with("POST /v1/messages"),
        "{}",
        s.request_line
    );
    assert!(s.header("x-api-key").is_some(), "{:?}", s.headers);
    assert_eq!(s.header("anthropic-version").as_deref(), Some("2023-06-01"));
    assert!(s.is_stream(), "expected stream:true");
    assert!(
        s.header("accept-encoding").unwrap_or_default().is_empty(),
        "accept-encoding leaked upstream (#60)"
    );
}

#[test]
fn codex_exec_answers_ok_through_proxy() {
    let Some(_v) = require_harness(&CODEX, "codex-ok") else {
        return;
    };
    let up = spawn_upstream();
    let proxy = start_proxy("codex-ok", InterventionMode::Observe, &up.url);
    let run = run_codex("ok", &proxy.base_url());
    answered_ok(&run, "codex");
    let seen = up.seen.lock().unwrap();
    let s = seen.first().expect("codex never reached the upstream");
    assert_eq!(s.request_line, "POST /v1/responses HTTP/1.1");
    assert!(
        s.header("authorization")
            .is_some_and(|a| a.starts_with("Bearer ")),
        "{:?}",
        s.headers
    );
    assert!(s.is_stream(), "expected stream:true");
    assert!(s.body.contains("\"model\":\"gpt-5\""), "model lost");
}

#[test]
fn codex_exec_upstream_400_is_a_failure_not_a_fake_ok() {
    let Some(_v) = require_harness(&CODEX, "codex-400") else {
        return;
    };
    let up = spawn_upstream_status(400);
    let proxy = start_proxy("codex-400", InterventionMode::Observe, &up.url);
    let run = run_codex("400", &proxy.base_url());
    failed_not_fake_ok(&run, "codex");
    assert!(
        !up.seen.lock().unwrap().is_empty(),
        "never reached upstream"
    );
}

#[test]
fn opencode_run_answers_ok_through_proxy() {
    let Some(_v) = require_harness(&OPENCODE, "opencode-ok") else {
        return;
    };
    let up = spawn_upstream();
    let proxy = start_proxy("opencode-ok", InterventionMode::Observe, &up.url);
    let run = run_opencode("ok", &proxy.base_url());
    answered_ok(&run, "opencode");
    anthropic_wire(&up.seen.lock().unwrap(), "claude-opus-4-5");
}

#[test]
fn opencode_run_upstream_400_is_a_failure_not_a_fake_ok() {
    let Some(_v) = require_harness(&OPENCODE, "opencode-400") else {
        return;
    };
    let up = spawn_upstream_status(400);
    let proxy = start_proxy("opencode-400", InterventionMode::Observe, &up.url);
    let run = run_opencode("400", &proxy.base_url());
    failed_not_fake_ok(&run, "opencode");
    assert!(
        !up.seen.lock().unwrap().is_empty(),
        "never reached upstream"
    );
}

#[test]
fn pi_print_answers_ok_through_proxy() {
    let Some(_v) = require_harness(&PI, "pi-ok") else {
        return;
    };
    let up = spawn_upstream();
    let proxy = start_proxy("pi-ok", InterventionMode::Observe, &up.url);
    let run = run_pi("ok", &proxy.base_url());
    answered_ok(&run, "pi");
    assert_eq!(run.stdout.trim(), "ok", "stderr: {}", run.stderr);
    anthropic_wire(&up.seen.lock().unwrap(), "claude-opus-4-5");
}

#[test]
fn pi_print_upstream_400_is_a_failure_not_a_fake_ok() {
    let Some(_v) = require_harness(&PI, "pi-400") else {
        return;
    };
    let up = spawn_upstream_status(400);
    let proxy = start_proxy("pi-400", InterventionMode::Observe, &up.url);
    let run = run_pi("400", &proxy.base_url());
    failed_not_fake_ok(&run, "pi");
    assert!(
        !up.seen.lock().unwrap().is_empty(),
        "never reached upstream"
    );
}
