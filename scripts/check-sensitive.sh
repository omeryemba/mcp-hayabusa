#!/usr/bin/env bash
# PreToolUse hook: blocks any tool call whose .tool_input.file_path looks
# like a sensitive file (.env, keys/certs, secrets/credentials directories,
# or a path containing "password"/"secret").
#
# Reads the Claude Code hook JSON payload from stdin, pulls out
# .tool_input.file_path via jq, and exits 2 with a block message on stderr
# when it matches a sensitive pattern. Any other path (or no file_path at
# all) is allowed: exits 0 with no output.

set -euo pipefail

payload="$(cat)"
file_path="$(echo "$payload" | jq -r '.tool_input.file_path // empty')"

if [[ -z "$file_path" ]]; then
    exit 0
fi

case "$file_path" in
    *.env|*.env.*|*.key|*.pem|*secrets/*|*credentials/*|*password*|*secret*)
        echo "BLOCKED: '$file_path' matches a sensitive file pattern (.env, *.key, *.pem, secrets/, credentials/, password, secret) and cannot be accessed by this tool call." >&2
        exit 2
        ;;
    *)
        exit 0
        ;;
esac
