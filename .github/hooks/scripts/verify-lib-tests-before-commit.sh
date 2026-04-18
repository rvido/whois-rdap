#!/usr/bin/env bash
set -euo pipefail

payload="$(cat)"

# Only intercept commit intents; do nothing for other tool calls.
is_commit=0
if [[ "$payload" == *"mcp_gitkraken_git_add_or_commit"* && "$payload" == *"\"action\":\"commit\""* ]]; then
  is_commit=1
fi
if [[ "$payload" == *"run_in_terminal"* && "$payload" == *"git commit"* ]]; then
  is_commit=1
fi

if [[ "$is_commit" -ne 1 ]]; then
  exit 0
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

# Enforce parser test gate only when src/lib.rs is staged for commit.
if ! git diff --cached --name-only | grep -qx "src/lib.rs"; then
  exit 0
fi

if cargo test --lib >/tmp/whois-rdap-hook-cargo-test-lib.log 2>&1; then
  exit 0
fi

cat <<'JSON'
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "src/lib.rs is staged, but cargo test --lib failed. Run cargo test --lib and fix failures before committing."
  },
  "systemMessage": "Commit blocked by hook: parser/library tests failed. See /tmp/whois-rdap-hook-cargo-test-lib.log for details."
}
JSON