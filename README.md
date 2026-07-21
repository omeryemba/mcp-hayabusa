# Hayabusa MCP Server

An MCP server exposing a `scan_evtx` tool that scans Windows EVTX files with
[Hayabusa](https://github.com/Yamato-Security/hayabusa) and returns the
detection results as JSON.

## Prerequisites

- Python 3.12+
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) installed, with
  `hayabusa.exe` on your `PATH` (or see `conftest.py` for how tests locate it)
- Python packages:

  ```
  pip install mcp pytest pywin32
  ```

## Files

| File            | Purpose                                                    |
|-----------------|-------------------------------------------------------------|
| `server.py`     | The MCP server and the `scan_evtx` tool                     |
| `test_server.py`| Pytest suite covering valid scans and error-handling cases  |
| `conftest.py`   | Ensures `hayabusa.exe` is on `PATH` when running pytest      |

## Running the server

```
python server.py
```

This starts the server on stdio and blocks waiting for an MCP client to
connect. There's no output on success — it just waits.

### Testing with the MCP Inspector

```
mcp dev server.py
```

Open the printed `http://localhost:6274/...` URL. In the connection form, set:

- **Command:** `python`
- **Arguments:** `server.py`

(Use a relative path for `server.py`, not an absolute one — an absolute
Windows path with backslashes can get mangled by the Inspector's query-string
handling and cause a silent connection failure.)

## Running the tests

```
python -m pytest test_server.py -v
```

`conftest.py` automatically adds `C:\Users\omery\tools\hayabusa` to `PATH`
before tests run, so this works without any manual setup even if that
directory isn't on your permanent system `PATH`.

### Test cases

- `test_valid_scan` — scans `samples/discovery_bloodhound.evtx` and checks
  the expected detection (Event ID 1102, "Log Cleared") comes back.
- `test_missing_file` — a nonexistent path returns a clean JSON error.
- `test_locked_file` — a file held open with an exclusive OS-level lock
  (via `win32file`) returns a clean JSON error instead of a misleading
  empty result.
- `test_corrupt_file` — non-EVTX content is readable but not a valid event
  log; Hayabusa itself treats this as "0 events loaded" and exits 0, so
  `scan_evtx` correctly returns `{"results": []}` rather than an error.

## Error handling in `scan_evtx`

`scan_evtx` returns errors as JSON (`{"error": "..."}`) rather than raising,
for:

- Missing input file
- Unreadable/locked input file
- Missing `hayabusa` executable
- Non-zero Hayabusa exit code
- Scan timeout (5 minutes)
- Malformed JSON output from Hayabusa
