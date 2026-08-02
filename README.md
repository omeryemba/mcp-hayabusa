# mcp-hayabusa

[![Tests](https://github.com/omeryemba/mcp-hayabusa/actions/workflows/test.yml/badge.svg)](https://github.com/omeryemba/mcp-hayabusa/actions/workflows/test.yml)
![Version](https://img.shields.io/badge/version-0.1.0-blue)

See [CHANGELOG.md](CHANGELOG.md) for release notes.

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa), the Rust-based Windows event log (.evtx) fast forensic timeline generator and threat hunting tool.

It shells out to a local `hayabusa` binary and exposes its analysis capabilities as MCP tools that an LLM client (Claude Desktop, Claude Code, etc.) can call directly against `.evtx` files.

## Prerequisites

- Python >= 3.10
- The [hayabusa](https://github.com/Yamato-Security/hayabusa/releases) binary, either on `PATH` or pointed to via the `HAYABUSA_BIN` environment variable.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
mcp-hayabusa
```

or

```bash
python -m mcp_hayabusa
```

The server communicates over stdio, so it's meant to be launched by an MCP client rather than run interactively.

### Example Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "mcp-hayabusa",
      "env": {
        "HAYABUSA_BIN": "C:\\tools\\hayabusa\\hayabusa.exe"
      }
    }
  }
}
```

## Tools

| Tool | Description |
| --- | --- |
| `hayabusa_version` | Get the installed hayabusa binary's version. |
| `hayabusa_list_profiles` | List available output profiles. |
| `hayabusa_update_rules` | Update the Sigma detection rule set. |
| `get_hayabusa_rules` | List available Hayabusa/Sigma detection rules from the local rules directory, with an optional keyword filter. |
| `hayabusa_csv_timeline` | Run `csv-timeline` over an `.evtx` file or directory; returns bounded rows + total count. |
| `hayabusa_json_timeline` | Run `json-timeline` over an `.evtx` file or directory; returns bounded JSON records + total count. |
| `hayabusa_eid_metrics` | Count event occurrences by Event ID. |
| `hayabusa_computer_metrics` | Count events per computer name. |
| `hayabusa_log_metrics` | Output `.evtx` file metadata (channels, event count, date range, etc.). |
| `hayabusa_logon_summary` | Summarize successful and failed logon events. |
| `hayabusa_pivot_keywords_list` | Extract pivot keywords (users, computers, IPs, processes, command lines, etc.) by category. |
| `hayabusa_extract_base64` | Extract and decode base64-encoded strings from event fields. |
| `hayabusa_config_critical_systems` | Detect likely domain controllers and file servers from the logs. |
| `hayabusa_search` | Keyword/regex search over `.evtx` event records. |
| `scan_evtx` | High-level first-pass scan: combines log metadata, a detection timeline (filtered by min level and an optional rule-title keyword filter), and event ID metrics. Returns a concise `summary`/`top_findings` result by default, or the full combined result with `output_format="full"`. |
| `analyze_coverage` | ATT&CK detection coverage over the installed rule set: an overall technique/tactic breakdown sorted weakest-covered first, or a focused answer for one `technique_id`. Coverage is measured only against techniques/tactics referenced by installed rules, not the full ATT&CK matrix — see the tool's `coverage_scope` caveat. |
| `suggest_rule` | Rank installed Sigma rules by relevance to a free-text query (title match > tags match > description match), optionally scoped to an ATT&CK `technique_id`. Finds and ranks *existing* rules; unlike `get_hayabusa_rules`'s exact substring match, results are relevance-ordered and capped at `max_suggestions`. |

## Resources

Unlike the tools above (which run analysis against `.evtx` files you point them at), these are read-only MCP resources for browsing the *installed detection rule set itself* — no `.evtx` file required. ATT&CK technique/tactic data is derived entirely from each Sigma rule's own `tags:` field (e.g. `attack.t1059.001`, `attack.execution`), not a bundled MITRE dataset, so it always matches whatever rules are actually installed. Each technique also gets a `mitre_url` (computed from the ID, e.g. `https://attack.mitre.org/techniques/T1059/001/`) and each tactic a hand-maintained `display_name` (e.g. `credential-access` → "Credential Access") — see `CLAUDE.md` for why technique IDs are *not* similarly enriched with human-readable names.

| Resource URI | Description |
| --- | --- |
| `hayabusa://rules` | Browsable rule catalog index, grouped by category, with per-category rule counts. |
| `hayabusa://rules/{rule_id}` | Full detail for a single rule by its Sigma `id`. |
| `hayabusa://attack/techniques` | ATT&CK technique ID -> detecting rules (detection coverage by technique). |
| `hayabusa://attack/techniques/{technique_id}` | Rules detecting a single ATT&CK technique, e.g. `hayabusa://attack/techniques/T1059.001`. |
| `hayabusa://attack/tactics` | ATT&CK tactic -> detecting rules (detection coverage by tactic). |

## Tests

```bash
pytest
```

All tests run against mocked subprocess calls, so no real `hayabusa` binary or `.evtx` file is required. Coverage is split across `tests/test_hayabusa.py` (the CLI wrapper functions), `tests/test_knowledge.py` (rule catalog/ATT&CK aggregation, against real small YAML fixtures), `tests/test_config.py` (binary resolution via `HAYABUSA_BIN`/`PATH`), and `tests/test_server.py` (the MCP tool and resource registrations themselves).

This does *not* apply to `validate-rule-execution.py` below, which is a separate, real-binary-required check, not part of `pytest`.

## Custom Detection Rule Validation

This project's custom Sigma rules under `rules/` are checked two ways:

- **`validate-rule.py`** (`.claude/skills/detection-engineering/scripts/validate-rule.py`) — metadata-only: ATT&CK tag, `level`, `falsepositives`, and that a sibling `.testcases.md` file exists. Needs only `pyyaml`, no real binary. Runs in CI (`validate-rules` job).
- **`validate-rule-execution.py`** (`.claude/skills/detection-engineering/scripts/validate-rule-execution.py`) — actually runs each rule against a real `.evtx` fixture via a real `hayabusa` binary and checks it fires/doesn't fire as documented in machine-readable ` ```yaml ` blocks embedded in the rule's `.testcases.md`. Requires the `mcp_hayabusa` package installed (`pip install -e .`) and a real `hayabusa` binary on `PATH`/`HAYABUSA_BIN`. Runs in CI (`validate-rule-execution` job, which downloads a pinned hayabusa binary), but you can also run it locally before treating a rule change as done:

  ```bash
  python .claude/skills/detection-engineering/scripts/validate-rule-execution.py rules/
  ```

  Fixtures are resolved from the `HAYABUSA_SAMPLE_EVTX_DIR` environment variable if set (point this at a fuller local corpus, e.g. EVTX-ATTACK-SAMPLES), otherwise from the small real fixtures vendored under `tests/fixtures/evtx/` (see `tests/fixtures/evtx/PROVENANCE.md` for their sourcing). Exit codes: `0` all cases passed, `1` a case contradicted its documented expectation, `2` a usage/parse error, `3` no failures but at least one rule's cases were all skipped (missing binary or fixture) — kept distinct from `0` so a missing prerequisite can never look like a clean pass.

## Threat Intelligence Ingestion

The `/ingest-ti` command (`.claude/commands/ingest-ti.md`) ingests IOC data from local files, normalizes it, and correlates it against this project's Sigma rule coverage. Two scripts back it, under `.claude/skills/ingest-ti/scripts/`:

- **`ingest_ti.py`** — normalizes one input file (a native `{type, value, confidence, source, first_seen, attack_technique, notes}` JSON list, or a MISP `Event.Attribute[]` JSON export) into that fixed schema. Needs only the Python standard library. Exit codes: `0` clean, `1` some indicators skipped/coerced, `2` usage/parse error.
- **`correlate_ti.py`** — takes 1+ normalized files, dedups/merges IOCs sharing a `(type, value)` key, and checks every ATT&CK technique they reference against this repo's installed Sigma rules via `analyze_coverage`/`suggest_rule` (`mcp_hayabusa.knowledge`). Optionally correlates against a saved Hayabusa scan result (`--hayabusa-result`) via a textual substring match. Exit codes: `0` clean, `1` issues found and/or an uncovered technique, `2` usage/parse error.

```bash
python .claude/skills/ingest-ti/scripts/ingest_ti.py intel/misp_export.json > /tmp/norm1.json
python .claude/skills/ingest-ti/scripts/correlate_ti.py /tmp/norm1.json --hayabusa-result artifacts/scan.json
```

v1 supports native and MISP JSON only — no STIX/TAXII or live TI feed APIs (see `.claude/skills/ingest-ti/SKILL.md`'s "Explicitly out of scope for v1"). Both scripts are unit-tested the normal mocked-nothing way in `tests/test_ingest_ti.py`/`tests/test_correlate_ti.py`, covered by the existing `pytest` job — no dedicated CI job is needed since neither script touches an external binary or network.

## Lint / Typecheck

```bash
ruff check .
mypy
```

Both run in CI (see the `lint` job in `.github/workflows/test.yml`), alongside `mypy tests` since the tests directory isn't covered by `[tool.mypy]`'s default package selection.
