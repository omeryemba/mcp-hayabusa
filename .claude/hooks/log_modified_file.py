#!/usr/bin/env python3
"""PostToolUse hook: logs the file path touched by a Write or Edit call.

Reads the hook payload Claude Code pipes on stdin and appends one line per
invocation to log_modified_file.py's sibling modified_files.log. Never
blocks the tool result -- always exits 0, even on a malformed payload.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent / "modified_files.log"


def main() -> None:
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        payload = json.load(sys.stdin)
        tool_name = payload.get("tool_name", "unknown")
        tool_input = payload.get("tool_input", {}) or {}
        tool_output = payload.get("tool_output", {}) or {}
        file_path = tool_input.get("file_path") or tool_output.get("file_path") or "unknown"
        line = f"{timestamp}\t{tool_name}\t{file_path}\n"
    except (json.JSONDecodeError, AttributeError) as exc:
        line = f"{timestamp}\tERROR\tcould not parse hook payload: {exc}\n"

    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line)

    sys.exit(0)


if __name__ == "__main__":
    main()
