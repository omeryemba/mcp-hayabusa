#!/bin/bash
MISSING=()

command -v jq >/dev/null 2>&1 || MISSING+=("jq")
command -v python3 >/dev/null 2>&1 || MISSING+=("python3")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "⚠️  Missing tools: ${MISSING[*]}" >&2
    echo "   jq is required for hooks to work." >&2
fi

exit 0
