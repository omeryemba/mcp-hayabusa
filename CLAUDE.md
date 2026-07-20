# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) CLI — a Rust-based Windows event log (`.evtx`) forensic timeline generator and threat hunting tool. It exposes Hayabusa's analysis commands as MCP tools so an LLM client (Claude Desktop, Claude Code, etc.) can run detection timelines and searches directly against `.evtx` files.

The server itself does no log parsing — it shells out to a locally installed `hayabusa` binary and parses *its* output (CSV / JSONL) into bounded, structured MCP tool results.

## Commands

```bash
# Install (editable, with test deps)
pip install -e ".[dev]"

# Run the server (stdio transport — meant to be launched by an MCP client, not run interactively)
mcp-hayabusa
python -m mcp_hayabusa

# Tests
pytest
pytest tests/test_hayabusa.py::test_csv_timeline_parses_and_truncates  # single test
```

There is no separate lint/typecheck command configured yet.

## Architecture

Three-module core under `src/mcp_hayabusa/`:

- **`config.py`** — resolves the path to the `hayabusa` binary: `HAYABUSA_BIN` env var if set, otherwise searched on `PATH`. Raises `HayabusaNotFoundError` if neither works. Every subprocess call goes through this.
- **`hayabusa.py`** — the actual CLI wrapper. All public functions (`version`, `list_profiles`, `update_rules`, `csv_timeline`, `json_timeline`, `search`) follow the same shape:
  1. Validate the `target` path exists (`_require_existing_path`).
  2. Build a `hayabusa <subcommand>` argv list (never through a shell — no shell-injection surface).
  3. For commands that produce result data (`csv_timeline`, `json_timeline`, `search`), write output to a temp file (hayabusa requires `-o <file>` for these; it won't stream structured results to stdout), then parse that file.
  4. Return a dict with `total_rows`/`records`, a `max_rows`-bounded slice, a `truncated` flag, the exact command that was run (for debuggability), and a trimmed `stderr_summary`.

  This bounding is deliberate: Hayabusa timelines over real event log sets can be huge, and tool results need to stay small enough to hand back to a model.

- **`server.py`** — thin `FastMCP` wrapper (from the official `mcp` SDK) that registers each `hayabusa.py` function as an `@mcp.tool()`. Tool docstrings are the descriptions the MCP client sees — keep them accurate when changing signatures. `main()` runs the server over stdio.

`__main__.py` just calls `server.main()` so `python -m mcp_hayabusa` works.

### Adding a new hayabusa subcommand as a tool

1. Add a wrapper function in `hayabusa.py` following the existing pattern (validate target → build argv → run via `_run` → parse temp-file output → return bounded dict).
2. Register it in `server.py` with `@mcp.tool()` and a docstring describing args/behavior (this is what the model sees).
3. Add a test in `tests/test_hayabusa.py` that monkeypatches `hayabusa._run` (and `_require_existing_path` where relevant) to avoid depending on a real `hayabusa` binary or real `.evtx` files.

## Testing conventions

Tests never invoke the real `hayabusa` binary. They monkeypatch `hayabusa._run` to return a `FakeResult` (and write whatever CSV/JSONL the real binary would have produced to the `-o` path passed in `args`), and monkeypatch `hayabusa._require_existing_path` when target-path validation would otherwise fail on a nonexistent path. See `tests/test_hayabusa.py` for the pattern.
