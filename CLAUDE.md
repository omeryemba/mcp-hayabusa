# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) CLI — a Rust-based Windows event log (`.evtx`) forensic timeline generator and threat hunting tool. It exposes Hayabusa's analysis commands (detection timelines, keyword search, event/computer/logon metrics, pivot keyword extraction, base64 extraction, critical-system detection) as MCP tools so an LLM client (Claude Desktop, Claude Code, etc.) can run them directly against `.evtx` files. See the README's Tools table for the full list.

The server itself does no log parsing — it shells out to a locally installed `hayabusa` binary and parses *its* output (mostly CSV/JSONL, plus plain text for the one subcommand that has no file-output option) into bounded, structured MCP tool results. One tool, `get_hayabusa_rules`, is the exception: it reads hayabusa's local Sigma rule YAML files directly instead of shelling out (see below).

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
  1. Validate the `target` path exists (`_require_existing_path`) — every other user-supplied path-like argument (`rules_dir` on `csv_timeline`/`json_timeline`/`get_hayabusa_rules`) is routed through the same function before use, for the same reason. See "Security / trust boundary" below for what this validation does and deliberately does not do.
  2. Build a `hayabusa <subcommand>` argv list (never through a shell — no shell-injection surface).
  3. Write output to a temp file (hayabusa requires `-o <file>` for structured results; it won't stream them to stdout), then parse that file.
  4. Return a dict with `total_rows`/`records`, a `max_rows`-bounded slice, a `truncated` flag, the exact command that was run (for debuggability), and a trimmed `stderr_summary`.

  This bounding is deliberate: Hayabusa timelines over real event log sets can be huge, and tool results need to stay small enough to hand back to a model.

  A few wrappers deviate because the hayabusa subcommands they call don't fit that shape — check `hayabusa <subcommand> --help` before assuming it does when adding a new one:
  - `logon_summary` writes two files from one `-o <prefix>` (`<prefix>-successful.csv`, `<prefix>-failed.csv`); `pivot_keywords_list` writes a dynamic, unbounded set of them (`<prefix>-<Category>.txt`, discovered by globbing) — both return a dict keyed by category/outcome instead of a flat row list.
  - `config_critical_systems` has no `-o` file option at all — hayabusa only prints to stdout — and drops into an interactive confirm prompt when it finds a match, which can't be answered non-interactively. `_run` guards against this for every wrapper: it sets `stdin=subprocess.DEVNULL` on the subprocess (so a stuck prompt can never read the MCP server's own stdio pipe) and converts a `TimeoutExpired` into a `CommandResult` carrying whatever partial stdout/stderr was captured (`TIMEOUT_RETURNCODE` sentinel) instead of raising, since a timeout on this subcommand usually means "found something and is stuck on the prompt," not a failure.
  - `scan_evtx` is different again: it's a high-level composite, not a hayabusa subcommand wrapper. It calls `log_metrics`, `csv_timeline`, and `eid_metrics` directly (no `_run`/subprocess of its own) and returns their results plus a small `summary` dict, giving a model one call for a first-pass look instead of three. `rule_filter` (case-insensitive substring match on each detection's `RuleTitle`) and `max_results` narrow just the detections, applied client-side after `csv_timeline` returns since hayabusa has no native keyword-based rule filter — both only see whatever `max_rows` already fetched, not the full unbounded detection set. `output_format` controls response shape only (`"summary"`, the default: aggregate counts + a bounded `top_findings` list; `"full"`: everything, i.e. the original always-returned shape), not filtering — passing `output_format="full"` with no `rule_filter`/`max_results` reproduces the pre-`output_format` return value exactly.
  - `get_hayabusa_rules` doesn't call `_run` or touch the hayabusa binary at all: hayabusa has no subcommand that lists its full rule catalog (only rules that actually fired during a scan appear in results), so it reads the Sigma rule YAML files directly with `pyyaml` from a rules directory that defaults to `<hayabusa binary's directory>/rules` (overridable via `rules_dir`). `keyword` filters case-insensitively against each rule's title/description/tags. Malformed rule files are skipped and counted in `parse_errors` rather than raising.

- **`server.py`** — thin `FastMCP` wrapper (from the official `mcp` SDK) that registers each `hayabusa.py` function as an `@mcp.tool()`. Tool docstrings are the descriptions the MCP client sees — keep them accurate when changing signatures. `main()` runs the server over stdio.

`__main__.py` just calls `server.main()` so `python -m mcp_hayabusa` works.

### Adding a new hayabusa subcommand as a tool

1. Add a wrapper function in `hayabusa.py` following the existing pattern (validate target → build argv → run via `_run` → parse temp-file output → return bounded dict) — but check `hayabusa <subcommand> --help` first; several existing wrappers deviate from this shape for reasons specific to their subcommand (see the deviations called out above).
2. Register it in `server.py` with `@mcp.tool()` and a docstring describing args/behavior (this is what the model sees).
3. Add a test in `tests/test_hayabusa.py` that monkeypatches `hayabusa._run` (and `_require_existing_path` where relevant) to avoid depending on a real `hayabusa` binary or real `.evtx` files.
4. Add a case to `tests/test_server.py` asserting the new tool is registered and that its kwargs are forwarded to the `hayabusa.py` function unchanged (monkeypatch the `hayabusa.*` function directly, not `_run`).

## Security / trust boundary

**MCP callers are trusted.** Anyone who can call a tool on this server can already run arbitrary commands as the OS account it's running under (that's what it means to be able to drive an MCP client at all). This server does not attempt to sandbox or restrict *which* files that caller can point it at — that's the whole point of the tool: an incident responder needs to run detections against `.evtx` files anywhere reachable from the box (mounted evidence drives, exported log copies, network shares, a different user's profile, etc.), and an artificial "allowed directories" restriction would just break that without stopping a caller who could read those paths some other way regardless.

**Filesystem access assumptions.** Every `target`, `rules_dir`, or similar path argument is passed straight through to `_require_existing_path` (`hayabusa.py`), which:
- Resolves the path (`Path(...).expanduser().resolve()`), which normalizes `..`/`.` segments and symlinks to their real, canonical location.
- Requires the resolved path to exist, raising `FileNotFoundError` (with the label and resolved path in the message) if not.
- Rejects empty/whitespace-only strings and any string containing a NUL byte (`\x00`) with `ValueError` — not because those are exploitable "traversal" per se, but because they aren't valid paths and can cause inconsistent behavior between Python's path handling and the OS/hayabusa's own argument parsing.

What this deliberately does **not** do: reject `..` segments, refuse absolute paths, or confine resolution to any base directory. A `..`-containing string is not special-cased — it's normalized by `.resolve()` like any other path and then subject to the exact same existence check as everything else. It grants no access beyond what the direct, already-resolved path would. There is no privilege boundary being crossed by allowing this, given the trust assumption above.

**Command injection.** All hayabusa invocations build an argv list and call `subprocess.run(argv, ...)` directly (see `_run`) — never `shell=True`, `os.system`, or string-interpolated commands — so there is no shell-metacharacter injection surface regardless of what a path or other argument contains.

## Testing conventions

Tests never invoke the real `hayabusa` binary, and are split across three files by what they exercise:

- **`tests/test_hayabusa.py`** — the CLI wrapper functions in `hayabusa.py`. Monkeypatches `hayabusa._run` to return a `FakeResult` (and writes whatever CSV/JSONL/text the real binary would have produced to the `-o` path passed in `args`), and monkeypatches `hayabusa._require_existing_path` when target-path validation would otherwise fail on a nonexistent path. Covers success/failure/edge-case paths for every public function, including the optional-flag argv construction, `json_timeline`'s JSONL quirks (bracket lines, trailing commas, malformed-line skipping), and `config_critical_systems`'s ANSI-stripping/category-name-normalization/timeout-as-partial-result handling. Also has direct tests for `_run` itself (`stdin=DEVNULL`, `TimeoutExpired` → `TIMEOUT_RETURNCODE` with partial output) by monkeypatching `subprocess.run`, and for `_require_existing_path`'s validation rules (empty/whitespace/NUL-byte rejection, `..` normalizing to a real location and still being existence-checked, not treated as a bypass). `scan_evtx` is tested differently since it's a composite: monkeypatches `hayabusa.log_metrics`/`csv_timeline`/`eid_metrics` directly (asserting `_run` is never called) rather than `_run`. `get_hayabusa_rules` is tested differently again: no `_run`/`_require_existing_path` mocking at all — tests write real, small Sigma-style YAML rule files into `tmp_path` and assert against the actual parsed output, since the function only ever touches the filesystem.
- **`tests/test_config.py`** — `resolve_hayabusa_binary()` in `config.py`. Uses `monkeypatch.setenv`/`delenv` for `HAYABUSA_BIN` and monkeypatches `shutil.which` to cover the env-var, `PATH`-fallback, and not-found cases without touching the real filesystem/`PATH`.
- **`tests/test_server.py`** — the `@mcp.tool()` registrations in `server.py`, i.e. the actual integration surface MCP clients call. Monkeypatches the `hayabusa.*` functions directly (not `_run`) and drives them through the real `FastMCP` instance via `asyncio.run(server.mcp.list_tools())` / `asyncio.run(server.mcp.call_tool(name, arguments))`, asserting that each tool is registered and that its kwargs are forwarded to `hayabusa.py` unchanged — this is what catches a signature/kwarg drift between a tool wrapper and the function it wraps.
