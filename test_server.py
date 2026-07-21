import asyncio
import json
from pathlib import Path

import pytest
import win32file

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_EVTX = BASE_DIR / "samples" / "discovery_bloodhound.evtx"


async def call_scan_evtx(file_path: str):
    params = StdioServerParameters(command="python", args=["server.py"], cwd=str(BASE_DIR))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool("scan_evtx", {"file_path": file_path})


@pytest.fixture
def locked_evtx(tmp_path):
    path = tmp_path / "locked_test.evtx"
    path.write_bytes(SAMPLE_EVTX.read_bytes())

    # Open with share_mode=0: no other process (including Hayabusa) can open this file at all.
    handle = win32file.CreateFile(
        str(path),
        win32file.GENERIC_READ,
        0,  # share mode: exclusive lock
        None,
        win32file.OPEN_EXISTING,
        0,
        None,
    )
    try:
        yield path
    finally:
        win32file.CloseHandle(handle)


@pytest.fixture
def corrupt_evtx(tmp_path):
    path = tmp_path / "corrupt_test.evtx"
    path.write_bytes(b"not a real evtx file")
    return path


def test_valid_scan():
    result = asyncio.run(call_scan_evtx(str(SAMPLE_EVTX)))
    parsed = json.loads(result.content[0].text)

    assert "error" not in parsed, f"Expected a successful scan, got: {parsed}"
    assert parsed["EventID"] == 1102, f"Expected EventID 1102 (Log Cleared), got: {parsed}"
    assert parsed["RuleTitle"] == "Log Cleared", f"Expected RuleTitle 'Log Cleared', got: {parsed}"


def test_missing_file():
    missing_path = str(BASE_DIR / "samples" / "does_not_exist.evtx")
    result = asyncio.run(call_scan_evtx(missing_path))
    parsed = json.loads(result.content[0].text)

    assert "error" in parsed, f"Expected a clean error for a missing file, got: {parsed}"


def test_locked_file(locked_evtx):
    result = asyncio.run(call_scan_evtx(str(locked_evtx)))
    parsed = json.loads(result.content[0].text)

    assert "error" in parsed, f"Expected a clean error for a locked file, got: {parsed}"


def test_corrupt_file(corrupt_evtx):
    result = asyncio.run(call_scan_evtx(str(corrupt_evtx)))
    parsed = json.loads(result.content[0].text)

    # Corrupt/non-EVTX content is readable, so it passes our readability check. Hayabusa
    # itself treats it as "0 event log files loaded" and exits 0 rather than failing, so
    # scan_evtx correctly reports an empty result set here, not an error.
    assert parsed == {"results": []}, f"Expected empty results for a corrupt file, got: {parsed}"
