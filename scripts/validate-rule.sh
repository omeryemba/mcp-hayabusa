#!/usr/bin/env bash
# PreToolUse/PostToolUse hook: validates a Sigma rule YAML file under rules/.
#
# Reads the Claude Code hook JSON payload from stdin, pulls out
# .tool_input.file_path via python (json module), and -- only when that path
# is a .yml/.yaml file inside rules/ -- checks with python (yaml.safe_load)
# that:
#   - a 'title' field exists
#   - a 'description' field exists
#   - 'tags' is a list containing at least one tag starting with 'attack.t'
#
# Any other file_path (non-YAML, or outside rules/) is ignored: exits 0
# with no output, so this hook is a no-op for unrelated tool calls.
#
# On rules/ YAML: always exits 2, printing either the validation errors or
# a success message to stderr.

set -euo pipefail

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

payload="$(cat)"
file_path="$("$PYTHON" -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    data = {}

if not isinstance(data, dict):
    data = {}

file_path = data.get("tool_input") or {}
if not isinstance(file_path, dict):
    file_path = {}

print(file_path.get("file_path") or "")
' <<< "$payload")"

if [[ -z "$file_path" ]]; then
    exit 0
fi

case "$file_path" in
    *rules/*.yml|*rules/*.yaml)
        ;;
    *)
        exit 0
        ;;
esac

if [[ ! -f "$file_path" ]]; then
    exit 0
fi

"$PYTHON" - "$file_path" <<'PYEOF' || true
import sys

import yaml

file_path = sys.argv[1]

with open(file_path, "r", encoding="utf-8") as f:
    rule = yaml.safe_load(f)

issues = []

if not isinstance(rule, dict):
    issues.append("Rule file does not contain a YAML mapping at the top level.")
    rule = {}

if not rule.get("title"):
    issues.append("'title' field is missing.")

if not rule.get("description"):
    issues.append("'description' field is missing.")

tags = rule.get("tags") or []
if not isinstance(tags, list):
    tags = [tags]
if not any(isinstance(t, str) and t.startswith("attack.t") for t in tags):
    issues.append("No ATT&CK technique tag found (expected a tag starting with 'attack.t').")

if issues:
    print(f"Sigma rule validation failed for {file_path}:", file=sys.stderr)
    for issue in issues:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)

print(f"Sigma rule validation passed for {file_path}.", file=sys.stderr)
PYEOF

exit 2
