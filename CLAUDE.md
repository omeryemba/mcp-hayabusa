# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) CLI — a Rust-based Windows event log (`.evtx`) forensic timeline generator and threat hunting tool. It exposes Hayabusa's analysis commands (detection timelines, keyword search, event/computer/logon metrics, pivot keyword extraction, base64 extraction, critical-system detection) as MCP tools so an LLM client (Claude Desktop, Claude Code, etc.) can run them directly against `.evtx` files. See the README's Tools table for the full list.

The server itself does no log parsing — it shells out to a locally installed `hayabusa` binary and parses *its* output (mostly CSV/JSONL, plus plain text for the one subcommand that has no file-output option) into bounded, structured MCP tool results.

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

# Lint / typecheck
ruff check .
mypy          # checks src/mcp_hayabusa (see [tool.mypy] in pyproject.toml)
mypy tests    # tests aren't covered by the mypy config's default package selection
```

## Architecture

Three-module core under `src/mcp_hayabusa/`:

- **`config.py`** — resolves the path to the `hayabusa` binary: `HAYABUSA_BIN` env var if set, otherwise searched on `PATH`. Raises `HayabusaNotFoundError` if neither works. Every subprocess call goes through this.
- **`hayabusa.py`** — the actual CLI wrapper. Most public functions (`csv_timeline`, `json_timeline`, `search`, `eid_metrics`, `computer_metrics`, `log_metrics`, `extract_base64`, and others) follow the same shape:
  1. Validate the `target` path exists (`_require_existing_path`).
  2. Build a `hayabusa <subcommand>` argv list (never through a shell — no shell-injection surface).
  3. Write output to a temp file (hayabusa requires `-o <file>` for structured results; it won't stream them to stdout), then parse that file.
  4. Return a dict with `total_rows`/`records`, a `max_rows`-bounded slice, a `truncated` flag, the exact command that was run (for debuggability), and a trimmed `stderr_summary`.

  This bounding is deliberate: Hayabusa timelines over real event log sets can be huge, and tool results need to stay small enough to hand back to a model.

  A few wrappers deviate because the hayabusa subcommands they call don't fit that shape — check `hayabusa <subcommand> --help` before assuming it does when adding a new one:
  - `logon_summary` writes two files from one `-o <prefix>` (`<prefix>-successful.csv`, `<prefix>-failed.csv`); `pivot_keywords_list` writes a dynamic, unbounded set of them (`<prefix>-<Category>.txt`, discovered by globbing) — both return a dict keyed by category/outcome instead of a flat row list.
  - `config_critical_systems` has no `-o` file option at all — hayabusa only prints to stdout — and drops into an interactive confirm prompt when it finds a match, which can't be answered non-interactively. `_run` guards against this for every wrapper: it sets `stdin=subprocess.DEVNULL` on the subprocess (so a stuck prompt can never read the MCP server's own stdio pipe) and converts a `TimeoutExpired` into a `CommandResult` carrying whatever partial stdout/stderr was captured (`TIMEOUT_RETURNCODE` sentinel) instead of raising, since a timeout on this subcommand usually means "found something and is stuck on the prompt," not a failure.
  - `scan_evtx` is different again: it's a high-level composite, not a hayabusa subcommand wrapper. It calls `log_metrics`, `csv_timeline`, and `eid_metrics` directly (no `_run`/subprocess of its own) and returns their results plus a small `summary` dict, giving a model one call for a first-pass look instead of three.

- **`server.py`** — thin `FastMCP` wrapper (from the official `mcp` SDK) that registers each `hayabusa.py` function as an `@mcp.tool()`. Tool docstrings are the descriptions the MCP client sees — keep them accurate when changing signatures. `main()` runs the server over stdio.

`__main__.py` just calls `server.main()` so `python -m mcp_hayabusa` works.

### Adding a new hayabusa subcommand as a tool

1. Add a wrapper function in `hayabusa.py` following the existing pattern (validate target → build argv → run via `_run` → parse temp-file output → return bounded dict) — but check `hayabusa <subcommand> --help` first; several existing wrappers deviate from this shape for reasons specific to their subcommand (see the deviations called out above).
2. Register it in `server.py` with `@mcp.tool()` and a docstring describing args/behavior (this is what the model sees).
3. Add a test in `tests/test_hayabusa.py` that monkeypatches `hayabusa._run` (and `_require_existing_path` where relevant) to avoid depending on a real `hayabusa` binary or real `.evtx` files.
4. Add a case to `tests/test_server.py` asserting the new tool is registered and that its kwargs are forwarded to the `hayabusa.py` function unchanged (monkeypatch the `hayabusa.*` function directly, not `_run`).

## Testing conventions

Tests never invoke the real `hayabusa` binary, and are split across three files by what they exercise:

- **`tests/test_hayabusa.py`** — the CLI wrapper functions in `hayabusa.py`. Monkeypatches `hayabusa._run` to return a `FakeResult` (and writes whatever CSV/JSONL/text the real binary would have produced to the `-o` path passed in `args`), and monkeypatches `hayabusa._require_existing_path` when target-path validation would otherwise fail on a nonexistent path. Covers success/failure/edge-case paths for every public function, including the optional-flag argv construction, `json_timeline`'s JSONL quirks (bracket lines, trailing commas, malformed-line skipping), and `config_critical_systems`'s ANSI-stripping/category-name-normalization/timeout-as-partial-result handling. Also has direct tests for `_run` itself (`stdin=DEVNULL`, `TimeoutExpired` → `TIMEOUT_RETURNCODE` with partial output) by monkeypatching `subprocess.run`. `scan_evtx` is tested differently since it's a composite: monkeypatches `hayabusa.log_metrics`/`csv_timeline`/`eid_metrics` directly (asserting `_run` is never called) rather than `_run`.
- **`tests/test_config.py`** — `resolve_hayabusa_binary()` in `config.py`. Uses `monkeypatch.setenv`/`delenv` for `HAYABUSA_BIN` and monkeypatches `shutil.which` to cover the env-var, `PATH`-fallback, and not-found cases without touching the real filesystem/`PATH`.
- **`tests/test_server.py`** — the `@mcp.tool()` registrations in `server.py`, i.e. the actual integration surface MCP clients call. Monkeypatches the `hayabusa.*` functions directly (not `_run`) and drives them through the real `FastMCP` instance via `asyncio.run(server.mcp.list_tools())` / `asyncio.run(server.mcp.call_tool(name, arguments))`, asserting that each tool is registered and that its kwargs are forwarded to `hayabusa.py` unchanged — this is what catches a signature/kwarg drift between a tool wrapper and the function it wraps.
