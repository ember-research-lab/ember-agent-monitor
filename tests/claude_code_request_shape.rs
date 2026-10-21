//! Claude Code request-shape test (#58), replaying the **wire capture** of the
//! real client (`tests/fixtures/claude-code/<version>/`, #64) instead of a
//! hand-written shape. The proxy must deliver `POST /v1/messages?beta=true`
//! with path+query and the captured headers intact, and never answer a
//! well-formed messages request with a 4xx (Claude Code renders any non-2xx
//! as "model may not exist").

mod cc_support;
use cc_support::*;
use ember_agent_monitor::types::InterventionMode;

#[test]
fn claude_code_capture_arrives_intact_and_is_not_4xx() {
    let cap = load_capture();
    let up = spawn_upstream();
    let proxy = start_proxy("shape", InterventionMode::Observe, &up.url);

    // Streaming (what the client really sends) and the non-stream variant.
    let streamed = String::from_utf8_lossy(&cap.replay(proxy.port, true)).to_string();
    let plain = String::from_utf8_lossy(&cap.replay(proxy.port, false)).to_string();
    for (name, resp) in [("stream", &streamed), ("non-stream", &plain)] {
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "[{}] proxy answered {name} with non-2xx: {}",
            cap.version,
            resp.lines().next().unwrap_or("")
        );
    }
    assert!(
        streamed.contains("event: message_stop"),
        "SSE reply must reach the client as SSE, not wrapped JSON (#60): {streamed}"
    );
    assert!(plain.contains("\"text\":\"ok\""), "{plain}");

    let seen = up.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "upstream should see both requests: {seen:?}");
    assert_eq!(seen[0].request_line, "POST /v1/messages?beta=true HTTP/1.1");
    // Every captured header (except hop-by-hop and accept-encoding, which the
    // proxy deliberately strips, #60) must reach upstream with its value.
    for h in &cap.headers {
        let (name, value) = h.split_once(':').unwrap();
        if name == "accept-encoding" {
            assert!(
                seen[0].header("accept-encoding").is_none(),
                "accept-encoding forwarded upstream"
            );
            continue;
        }
        assert_eq!(
            seen[0].header(name).as_deref(),
            Some(value.trim()),
            "captured header {name} lost or altered ({})",
            cap.version
        );
    }
    assert_eq!(seen[0].body, cap.body, "request body altered in transit");
}
