# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-07-23

Initial release.

### Added

- Initial MCP (Model Context Protocol) server release, exposing Hayabusa as a set of MCP tools an LLM client can call directly against `.evtx` files.
- Hayabusa MCP tool integration: each tool shells out to a locally installed `hayabusa` binary (resolved via `HAYABUSA_BIN` or `PATH`) and parses its output into bounded, structured results.
- Forensic analysis tools covering the following `hayabusa` subcommands:
  - `csv-timeline` — DFIR detection timeline, CSV output
  - `json-timeline` — DFIR detection timeline, JSON/JSONL output
  - `search` — keyword/regex search over event records
  - `eid-metrics` — event counts by Event ID
  - `logon-summary` — successful/failed logon summary
  - `log-metrics` — `.evtx` file metadata
  - `computer-metrics` — event counts per computer name
  - `extract-base64` — extraction/decoding of base64 strings from event fields
  - `pivot-keywords-list` — pivot keyword extraction (users, computers, IPs, processes, command lines, etc.) by category
  - `config-critical-systems` — detection of likely domain controllers and file servers
  - `version` — installed hayabusa binary version
  - `list-profiles` — available output profiles
  - `update-rules` — Sigma detection rule set updates
- Testing support: full pytest coverage split across `tests/test_hayabusa.py` (CLI wrapper functions), `tests/test_config.py` (binary resolution), and `tests/test_server.py` (MCP tool registrations), all running against mocked subprocess calls with no dependency on a real `hayabusa` binary or `.evtx` files.
- CI workflow support: GitHub Actions workflow running the test suite on Python 3.10, 3.11, and 3.12.
- Documentation improvements: README usage/install/config instructions and a full Tools reference table; CLAUDE.md architecture and testing-convention notes for future contributors.
