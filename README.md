# mcp-hayabusa

[![Tests](https://github.com/omeryemba/mcp-hayabusa/actions/workflows/test.yml/badge.svg)](https://github.com/omeryemba/mcp-hayabusa/actions/workflows/test.yml)

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
| `hayabusa_csv_timeline` | Run `csv-timeline` over an `.evtx` file or directory; returns bounded rows + total count. |
| `hayabusa_json_timeline` | Run `json-timeline` over an `.evtx` file or directory; returns bounded JSON records + total count. |
| `hayabusa_search` | Keyword/regex search over `.evtx` event records. |

## Tests

```bash
pytest
```

All tests run against mocked subprocess calls, so no real `hayabusa` binary or `.evtx` file is required. Coverage is split across `tests/test_hayabusa.py` (the CLI wrapper functions), `tests/test_config.py` (binary resolution via `HAYABUSA_BIN`/`PATH`), and `tests/test_server.py` (the MCP tool registrations themselves).
