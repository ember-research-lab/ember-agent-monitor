#!/usr/bin/env bash
# install.sh — the only sanctioned way to put an ember-agent build live (#64).
#
# build -> keep the live binary as <bin>.prev -> restart the unit -> acceptance
# (health + a real client must get `ok` for every model, through the live port)
# -> on ANY failure reinstall .prev, restart, re-check health, exit non-zero.
#
# Env (defaults are the live deployment; override only to test this script
# against a throwaway unit/port, never to skip the check):
#   UNIT          systemd user unit            (ember-agent-monitor.service)
#   PORT          proxy port the unit serves   (9452)
#   BIN           binary the unit executes     (<repo>/target/release/ember-agent)
#   BUILD_CMD     build step                   (cargo build --release)
#   MODELS        models to acceptance-test    (fable opus)
#   ACCEPT_ISOLATED=1  run the client with a scratch HOME/config and a dummy
#                 API key (for throwaway units whose upstream is a mock);
#                 default: inherit the caller's environment and credentials.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT="${UNIT:-ember-agent-monitor.service}"
PORT="${PORT:-9452}"
BIN="${BIN:-$REPO/target/release/ember-agent}"
BUILD_CMD="${BUILD_CMD:-cargo build --release}"
MODELS="${MODELS:-fable opus}"
BASE="http://127.0.0.1:$PORT"
PREV="$BIN.prev"
log() { printf '[install] %s\n' "$*" >&2; }

# Replace a possibly-running binary: cp onto it fails with "Text file busy";
# rename-over works and is atomic.
put() { cp -f "$1" "$2.new" && mv -f "$2.new" "$2"; }

wait_health() { # up to ~15s
  for _ in $(seq 1 30); do
    curl -fsS --max-time 2 "$BASE/health" 2>/dev/null | grep -q '"status":"ok"' && return 0
    sleep 0.5
  done
  return 1
}

accept_claude() { # $1 = model
  command -v claude >/dev/null 2>&1 || { log "FAIL: claude not on PATH; acceptance cannot run"; return 1; }
  local out rc
  if [ "${ACCEPT_ISOLATED:-0}" = 1 ]; then
    local scratch; scratch="$(mktemp -d)"
    out="$(cd "$scratch" && env -i PATH="$PATH" HOME="$scratch" CLAUDE_CONFIG_DIR="$scratch/cfg" \
      ANTHROPIC_BASE_URL="$BASE" ANTHROPIC_API_KEY=sk-ant-dummy-install-gate \
      timeout 120 claude -p "reply with the single word ok" --model "$1" </dev/null 2>&1)"
    rc=$?
    rm -rf "$scratch"
  else
    out="$(ANTHROPIC_BASE_URL="$BASE" timeout 120 claude -p "reply with the single word ok" --model "$1" </dev/null 2>&1)"
    rc=$?
  fi
  log "claude -p --model $1 -> rc=$rc: $(printf '%s' "$out" | head -c 300)"
  [ $rc -eq 0 ] && [ "$(printf '%s' "$out" | tr -d '[:space:]')" = "ok" ] && ! printf '%s' "$out" | grep -q 'API Error'
}

acceptance() {
  wait_health || { log "FAIL: $BASE/health never answered"; return 1; }
  log "health ok ($(claude --version 2>/dev/null || echo 'claude version unknown'))"
  for m in $MODELS; do accept_claude "$m" || { log "FAIL: acceptance for model $m"; return 1; }; done
  return 0
}

rollback() {
  log "ROLLBACK: reinstalling previous binary"
  if [ -f "$PREV" ]; then
    put "$PREV" "$BIN" && systemctl --user restart "$UNIT"
    if wait_health; then log "rolled back; $BASE/health ok on the previous build"
    else log "ROLLBACK FAILED: previous build does not answer health either; inspect: journalctl --user -u $UNIT"; fi
  else
    log "ROLLBACK IMPOSSIBLE: no $PREV (first install?); unit left as is"
  fi
}

cd "$REPO" || exit 2
if [ -f "$BIN" ]; then put "$BIN" "$PREV" && log "kept previous binary at $PREV"; else log "no existing $BIN: nothing to roll back to"; fi
log "build: $BUILD_CMD"
if ! (eval "$BUILD_CMD"); then log "FAIL: build"; [ -f "$PREV" ] && put "$PREV" "$BIN"; exit 1; fi
log "restart $UNIT"
systemctl --user restart "$UNIT" || { log "FAIL: restart"; rollback; exit 1; }
if acceptance; then log "OK: new build is live and answered ok for: $MODELS"; exit 0; fi
rollback
exit 1
