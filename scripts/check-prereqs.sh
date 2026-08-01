#!/bin/bash
MISSING=()

command -v jq >/dev/null 2>&1 || MISSING+=("jq")

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done
[ -n "$PYTHON" ] || MISSING+=("python3/python")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "⚠️  Missing tools: ${MISSING[*]}" >&2
    echo "   jq is required for hooks to work." >&2
fi

exit 0
