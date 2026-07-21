"""Thin subprocess wrapper around the hayabusa CLI.

Each analysis function writes hayabusa's output to a temp file (hayabusa
requires -o to be a file, not stdout, for csv/json timelines and search),
parses it, and returns a bounded number of rows so results stay small
enough to hand back to a model.
"""

from __future__ import annotations

import csv
import json
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import resolve_hayabusa_binary

DEFAULT_TIMEOUT_SEC = 600
MAX_ROWS_RETURNED = 200


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


def _run(args: list[str], timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> CommandResult:
    binary = resolve_hayabusa_binary()
    command = [binary, *args]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        check=False,
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr, command)


def _require_existing_path(path_str: str, label: str = "target") -> Path:
    path = Path(path_str).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    return path


def _command_str(result: CommandResult) -> str:
    return " ".join(shlex.quote(part) for part in result.command)


def version() -> str:
    result = _run(["--version"], timeout_sec=30)
    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(f"hayabusa --version failed: {result.stderr}")
    return output


def list_profiles() -> str:
    result = _run(["list-profiles"], timeout_sec=30)
    if result.returncode != 0:
        raise RuntimeError(f"hayabusa list-profiles failed: {result.stderr}")
    return result.stdout.strip()


def update_rules(timeout_sec: int = 300) -> str:
    result = _run(["update-rules"], timeout_sec=timeout_sec)
    # hayabusa exits non-zero when rules are already at the latest commit.
    output = result.stdout.strip() or result.stderr.strip()
    if result.returncode not in (0, 1):
        raise RuntimeError(f"hayabusa update-rules failed: {result.stderr}")
    return output


def csv_timeline(
    target: str,
    *,
    profile: str | None = None,
    min_level: str | None = None,
    rules_dir: str | None = None,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "timeline.csv"
        args = [
            "csv-timeline",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
            "-w",
        ]
        if profile:
            args += ["-p", profile]
        if min_level:
            args += ["-m", min_level]
        if rules_dir:
            args += ["-r", rules_dir]

        result = _run(args, timeout_sec=timeout_sec)
        if not output_path.exists():
            raise RuntimeError(
                "hayabusa csv-timeline produced no output file.\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        rows: list[dict] = []
        total = 0
        with output_path.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                total += 1
                if len(rows) < max_rows:
                    rows.append(row)

    return {
        "command": _command_str(result),
        "total_rows": total,
        "returned_rows": len(rows),
        "truncated": total > len(rows),
        "rows": rows,
        "stderr_summary": result.stderr.strip()[-2000:] if result.stderr else "",
    }


def json_timeline(
    target: str,
    *,
    profile: str | None = None,
    min_level: str | None = None,
    rules_dir: str | None = None,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "timeline.jsonl"
        args = [
            "json-timeline",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
            "-w",
            "-L",
        ]
        if profile:
            args += ["-p", profile]
        if min_level:
            args += ["-m", min_level]
        if rules_dir:
            args += ["-r", rules_dir]

        result = _run(args, timeout_sec=timeout_sec)
        if not output_path.exists():
            raise RuntimeError(
                "hayabusa json-timeline produced no output file.\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        records: list[dict] = []
        total = 0
        with output_path.open(encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip().rstrip(",")
                if not line or line in "[]":
                    continue
                total += 1
                if len(records) < max_rows:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    return {
        "command": _command_str(result),
        "total_rows": total,
        "returned_rows": len(records),
        "truncated": total > len(records),
        "records": records,
        "stderr_summary": result.stderr.strip()[-2000:] if result.stderr else "",
    }


def search(
    target: str,
    keywords: list[str],
    *,
    regex: bool = False,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)
    if not keywords:
        raise ValueError("At least one keyword is required")

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "search.csv"
        args = [
            "search",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
            "-w",
        ]
        flag = "-r" if regex else "-k"
        for keyword in keywords:
            args += [flag, keyword]

        result = _run(args, timeout_sec=timeout_sec)

        rows: list[dict] = []
        total = 0
        if output_path.exists():
            with output_path.open(newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    total += 1
                    if len(rows) < max_rows:
                        rows.append(row)

    return {
        "command": _command_str(result),
        "total_rows": total,
        "returned_rows": len(rows),
        "truncated": total > len(rows),
        "rows": rows,
        "stderr_summary": result.stderr.strip()[-2000:] if result.stderr else "",
    }
