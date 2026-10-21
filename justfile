# ember-agent-monitor tasks. `just` is optional: every recipe is a plain command.

# Put a build live: build, restart, real-client acceptance, rollback on failure (#64).
# This is the ONLY sanctioned way to update the running service.
install:
    scripts/install.sh

# Mandatory before every PR/merge where CI cannot run the real client (#64).
gate:
    cargo fmt --all -- --check
    cargo clippy --all-targets --no-deps -- -D warnings
    CI=true cargo test --test claude_code_e2e --test harness_e2e --test claude_code_request_shape --test anthropic_forwarding

# Refresh tests/fixtures/claude-code/<installed version>/ from the real client.
capture-claude-code:
    cargo test --test claude_code_e2e capture_claude_code_fixture -- --ignored --nocapture
