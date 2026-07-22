"""Thin subprocess wrapper around the hayabusa CLI.

Each analysis function writes hayabusa's output to a temp file (hayabusa
requires -o to be a file, not stdout, for csv/json timelines and search),
parses it, and returns a bounded number of rows so results stay small
enough to hand back to a model.
"""

from __future__ import annotations

import csv
import json
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import resolve_hayabusa_binary

DEFAULT_TIMEOUT_SEC = 600
MAX_ROWS_RETURNED = 200

# Synthetic returncode used when a command is killed for exceeding timeout_sec
# (real hayabusa exit codes are always >= 0).
TIMEOUT_RETURNCODE = -1


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


def _run(args: list[str], timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> CommandResult:
    binary = resolve_hayabusa_binary()
    command = [binary, *args]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
            # Some subcommands (e.g. config-critical-systems) can drop into an
            # interactive confirmation prompt when they find results. Without
            # this, the child would inherit our own stdin -- the MCP client's
            # JSON-RPC pipe -- and could hang reading it or corrupt the
            # protocol stream. /dev/null guarantees it just sees EOF.
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        # Surface whatever was captured before the kill instead of raising,
        # since a stuck interactive prompt is a meaningful outcome on its own
        # (see config_critical_systems), not just an execution failure.
        return CommandResult(TIMEOUT_RETURNCODE, exc.stdout or "", exc.stderr or "", command)
    return CommandResult(proc.returncode, proc.stdout, proc.stderr, command)


def _require_existing_path(path_str: str, label: str = "target") -> Path:
    path = Path(path_str).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    return path


def _command_str(result: CommandResult) -> str:
    return " ".join(shlex.quote(part) for part in result.command)


_VERSION_RE = re.compile(r"Hayabusa\s+(v[\d][^\r\n]*)", re.IGNORECASE)


def version() -> str:
    # hayabusa has no --version flag; the version is printed as the first
    # line of its `help` banner (e.g. "Hayabusa v3.10.0 - ... Release").
    result = _run(["help"], timeout_sec=30)
    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(f"hayabusa help failed: {result.stderr}")
    match = _VERSION_RE.search(output)
    if not match:
        raise RuntimeError(f"could not parse hayabusa version from help output: {output!r}")
    return match.group(1).strip()


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


def eid_metrics(
    target: str,
    *,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "eid-metrics.csv"
        args = [
            "eid-metrics",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
        ]

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


def extract_base64(
    target: str,
    *,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "extract-base64.csv"
        args = [
            "extract-base64",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
        ]

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


def log_metrics(
    target: str,
    *,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "log-metrics.csv"
        args = [
            "log-metrics",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
        ]

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


def computer_metrics(
    target: str,
    *,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_path = Path(tmpdir) / "computer-metrics.csv"
        args = [
            "computer-metrics",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_path),
        ]

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


def logon_summary(
    target: str,
    *,
    max_rows: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_prefix = Path(tmpdir) / "logon-summary"
        args = [
            "logon-summary",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_prefix),
        ]

        result = _run(args, timeout_sec=timeout_sec)

        def _read_csv(path: Path) -> tuple[list[dict], int]:
            rows: list[dict] = []
            total = 0
            if path.exists():
                with path.open(newline="", encoding="utf-8-sig") as f:
                    for row in csv.DictReader(f):
                        total += 1
                        if len(rows) < max_rows:
                            rows.append(row)
            return rows, total

        # hayabusa writes two files from the -o prefix: "<prefix>-successful.csv"
        # and "<prefix>-failed.csv".
        successful_rows, successful_total = _read_csv(
            output_prefix.with_name(output_prefix.name + "-successful.csv")
        )
        failed_rows, failed_total = _read_csv(
            output_prefix.with_name(output_prefix.name + "-failed.csv")
        )

    return {
        "command": _command_str(result),
        "successful": {
            "total_rows": successful_total,
            "returned_rows": len(successful_rows),
            "truncated": successful_total > len(successful_rows),
            "rows": successful_rows,
        },
        "failed": {
            "total_rows": failed_total,
            "returned_rows": len(failed_rows),
            "truncated": failed_total > len(failed_rows),
            "rows": failed_rows,
        },
        "stderr_summary": result.stderr.strip()[-2000:] if result.stderr else "",
    }


def pivot_keywords_list(
    target: str,
    *,
    min_level: str | None = None,
    max_keywords: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    target_path = _require_existing_path(target)

    with tempfile.TemporaryDirectory(prefix="mcp_hayabusa_") as tmpdir:
        output_prefix = Path(tmpdir) / "pivot-keywords"
        args = [
            "pivot-keywords-list",
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "-o",
            str(output_prefix),
            "-w",
        ]
        if min_level:
            args += ["-m", min_level]

        result = _run(args, timeout_sec=timeout_sec)

        # hayabusa writes one file per pivot keyword category, named
        # "<prefix>-<Category Name>.txt" (categories come from
        # rules/config/pivot_keywords.txt, e.g. "Users", "IP Addresses").
        categories: dict[str, dict] = {}
        prefix_name = output_prefix.name
        for path in sorted(Path(tmpdir).glob(f"{prefix_name}-*.txt")):
            category = path.stem[len(prefix_name) + 1 :]
            with path.open(encoding="utf-8-sig") as f:
                values = [line.strip() for line in f if line.strip()]
            total = len(values)
            categories[category] = {
                "total_keywords": total,
                "returned_keywords": min(total, max_keywords),
                "truncated": total > max_keywords,
                "keywords": values[:max_keywords],
            }

    return {
        "command": _command_str(result),
        "categories": categories,
        "stderr_summary": result.stderr.strip()[-2000:] if result.stderr else "",
    }


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CATEGORY_FOUND_RE = re.compile(r"^(.+) found \(\d+\):$")
_CATEGORY_NONE_RE = re.compile(r"^No (.+) found\.$")

# The "none found" line prints the Rust enum's Debug name (e.g.
# "DomainController"), while the "found" line prints its pretty display name
# (e.g. "Domain Controllers"). Normalize both to the pretty form so a category
# has one consistent key regardless of whether it had matches.
_CRITICAL_SYSTEM_CATEGORY_NAMES = {
    "DomainController": "Domain Controllers",
    "FileServer": "File Servers",
}


def config_critical_systems(
    target: str,
    *,
    max_hosts: int = MAX_ROWS_RETURNED,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> dict:
    # Unlike every other subcommand, this one has no -o file output -- it
    # only prints to stdout, and it drops into an interactive confirmation
    # prompt ("add these hosts to critical_systems.txt?") for each category
    # where it finds matches. That prompt can't be answered here (see _run's
    # stdin=DEVNULL), so hayabusa just hangs on it until timeout_sec kills
    # the process. That is expected, not an error: hayabusa prints a
    # category's results before prompting about it, so the partial stdout
    # _run recovers on timeout already contains everything found for
    # categories reached before the hang. Any category after the one it got
    # stuck on is simply not in the output at all -- "not present in
    # categories" does not mean "none found" when prompt_interrupted is True.
    target_path = _require_existing_path(target)

    args = [
        "config-critical-systems",
        "-d" if target_path.is_dir() else "-f",
        str(target_path),
        "-K",
        "-q",
    ]

    result = _run(args, timeout_sec=timeout_sec)
    output = _ANSI_ESCAPE_RE.sub("", result.stdout)

    prompt_interrupted = result.returncode == TIMEOUT_RETURNCODE
    if not prompt_interrupted and result.returncode != 0 and not output.strip():
        raise RuntimeError(f"hayabusa config-critical-systems failed: {result.stderr}")

    categories: dict[str, dict] = {}
    current_category: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            current_category = None
            continue
        found_match = _CATEGORY_FOUND_RE.match(line)
        none_match = _CATEGORY_NONE_RE.match(line)
        if found_match:
            current_category = found_match.group(1)
            categories[current_category] = {"hosts": []}
        elif none_match:
            debug_name = none_match.group(1)
            categories[_CRITICAL_SYSTEM_CATEGORY_NAMES.get(debug_name, debug_name)] = {"hosts": []}
            current_category = None
        elif current_category is not None:
            categories[current_category]["hosts"].append(line)

    for category in categories.values():
        hosts = category.pop("hosts")
        total = len(hosts)
        category["total_hosts"] = total
        category["returned_hosts"] = min(total, max_hosts)
        category["truncated"] = total > max_hosts
        category["hosts"] = hosts[:max_hosts]

    return {
        "command": _command_str(result),
        "categories": categories,
        "prompt_interrupted": prompt_interrupted,
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
