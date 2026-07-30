#!/usr/bin/env python3
"""Execution-based test runner for this project's custom Sigma rules.

Usage:
    python validate-rule-execution.py <rule.yml | rules-dir> [...]

Unlike validate-rule.py (which only checks rule *metadata*), this script
actually runs each rule against a real .evtx fixture via hayabusa and
verifies it fires (or doesn't fire) as documented in machine-readable YAML
blocks embedded in the rule's sibling '<rule-stem>.testcases.md' file:

    ```yaml
    fixture: admin_share_access_smb.evtx
    expect: fires        # or: no_fire
    min_hits: 1           # optional, default 1, ignored when expect: no_fire
    ```

Fixture files are resolved from the HAYABUSA_SAMPLE_EVTX_DIR environment
variable if set, otherwise from the vendored tests/fixtures/evtx/
directory in this repo.

This script requires the mcp_hayabusa package to be installed
(`pip install -e .`) and a real hayabusa binary on PATH or via
HAYABUSA_BIN -- unlike validate-rule.py, which only needs pyyaml. It runs
in CI (the validate-rule-execution job in .github/workflows/test.yml,
which installs a pinned hayabusa binary); you can also run it manually
for faster feedback before treating a rule change as done.

Prints a JSON report to stdout. Exit codes:
    0 - every rule's cases passed (no failures, errors, or skips)
    1 - at least one case contradicted its documented expectation (a real
        rule-logic failure)
    2 - a usage/parse error: missing rule file, missing/empty testcases
        file, malformed YAML block, or hayabusa itself errored while
        trying to run a rule
    3 - no failures/errors, but at least one rule's cases were all
        skipped (missing hayabusa binary or missing fixture file) -- so a
        missing prerequisite can never look identical to a clean pass
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from mcp_hayabusa.config import HayabusaNotFoundError, resolve_hayabusa_binary
from mcp_hayabusa.hayabusa import csv_timeline

TEST_CASE_FILE_SUFFIX = ".testcases.md"
VALID_EXPECTATIONS = {"fires", "no_fire"}

_HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
_YAML_FENCE_OPEN_RE = re.compile(r"^```ya?ml\s*$")
_FENCE_CLOSE_RE = re.compile(r"^```\s*$")


def resolve_fixture_dir() -> Path:
    env_dir = os.environ.get("HAYABUSA_SAMPLE_EVTX_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    # Vendored default: tests/fixtures/evtx/, relative to the repo this
    # script lives in (four levels up from .claude/skills/*/scripts/).
    repo_root = Path(__file__).resolve().parents[4]
    return repo_root / "tests" / "fixtures" / "evtx"


def iter_yaml_blocks(testcases_path: Path) -> list[dict[str, Any]]:
    """Extract explicitly-tagged ```yaml fenced blocks from a .testcases.md file.

    Untagged ``` fences (the existing hand-written field:value example
    blocks) are left alone -- only a fence opened with ```yaml or ```yml is
    treated as a machine-readable test case.
    """
    blocks: list[dict[str, Any]] = []
    heading = ""
    in_yaml_fence = False
    fence_lines: list[str] = []
    fence_start_line = 0

    text = testcases_path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if in_yaml_fence:
            if _FENCE_CLOSE_RE.match(line):
                blocks.append(
                    {"heading": heading, "line": fence_start_line, "raw": "\n".join(fence_lines)}
                )
                in_yaml_fence = False
                fence_lines = []
            else:
                fence_lines.append(line)
            continue

        heading_match = _HEADING_RE.match(line)
        if heading_match:
            heading = heading_match.group(1).strip()
            continue

        if _YAML_FENCE_OPEN_RE.match(line):
            in_yaml_fence = True
            fence_start_line = lineno
            fence_lines = []

    return blocks


def parse_case(block: dict[str, Any]) -> dict[str, Any]:
    """Parse and schema-check one extracted YAML block.

    Returns a normalized case dict, or a dict with a truthy "parse_error"
    key -- a syntax or schema problem is always surfaced as an error, never
    silently dropped, since that would defeat the point of an
    execution-based check.
    """
    try:
        data = yaml.safe_load(block["raw"])
    except yaml.YAMLError as exc:
        return {**block, "parse_error": f"YAML syntax error: {exc}"}

    if not isinstance(data, dict):
        return {**block, "parse_error": "block did not parse to a YAML mapping"}

    fixture = data.get("fixture")
    expect = data.get("expect")
    min_hits = data.get("min_hits", 1)

    if not isinstance(fixture, str) or not fixture.strip():
        return {**block, "parse_error": "'fixture' must be a non-empty string"}
    if expect not in VALID_EXPECTATIONS:
        valid = sorted(VALID_EXPECTATIONS)
        return {**block, "parse_error": f"'expect' must be one of {valid}, found: {expect!r}"}
    if not isinstance(min_hits, int) or min_hits < 1:
        return {**block, "parse_error": f"'min_hits' must be a positive integer, found: {min_hits!r}"}

    warning = None
    heading_lower = block["heading"].lower()
    if "negative" in heading_lower and expect == "fires":
        warning = f"heading '{block['heading']}' says Negative but expect: fires"
    elif "positive" in heading_lower and expect == "no_fire":
        warning = f"heading '{block['heading']}' says Positive but expect: no_fire"

    return {
        **block,
        "fixture": fixture.strip(),
        "expect": expect,
        "min_hits": min_hits,
        "warning": warning,
    }


def find_testcases_file(rule_path: Path) -> Path | None:
    candidate = rule_path.with_name(f"{rule_path.stem}{TEST_CASE_FILE_SUFFIX}")
    return candidate if candidate.is_file() and candidate.stat().st_size > 0 else None


def run_case(
    case: dict[str, Any],
    rule_path: Path,
    fixture_dir: Path,
    hayabusa_available: bool,
) -> dict[str, Any]:
    heading = case["heading"]
    fixture_name = case["fixture"]

    if not hayabusa_available:
        return {
            "heading": heading,
            "fixture": fixture_name,
            "outcome": "skipped",
            "detail": "hayabusa binary not found (set HAYABUSA_BIN or add it to PATH)",
        }

    fixture_path = fixture_dir / fixture_name
    if not fixture_path.is_file():
        return {
            "heading": heading,
            "fixture": fixture_name,
            "outcome": "skipped",
            "detail": (
                f"fixture file not found: {fixture_path} "
                "(set HAYABUSA_SAMPLE_EVTX_DIR or vendor it under tests/fixtures/evtx/)"
            ),
        }

    try:
        result = csv_timeline(str(fixture_path), rules_dir=str(rule_path))
    except (RuntimeError, HayabusaNotFoundError) as exc:
        return {
            "heading": heading,
            "fixture": fixture_name,
            "outcome": "error",
            "detail": f"hayabusa execution failed: {exc}",
        }

    if result.get("hayabusa_errors"):
        return {
            "heading": heading,
            "fixture": fixture_name,
            "outcome": "error",
            "detail": f"hayabusa reported a per-file error: {result['hayabusa_errors']}",
        }

    hits = result["total_rows"]
    expect = case["expect"]
    min_hits = case["min_hits"]

    if expect == "fires":
        passed = hits >= min_hits
        detail = f"expected >= {min_hits} hit(s), got {hits}"
    else:
        passed = hits == 0
        detail = f"expected 0 hits, got {hits}"

    return {
        "heading": heading,
        "fixture": fixture_name,
        "expect": expect,
        "min_hits": min_hits,
        "hits": hits,
        "outcome": "pass" if passed else "fail",
        "detail": detail,
        "warning": case.get("warning"),
    }


_STATUS_PRECEDENCE = {"error": 3, "fail": 2, "skipped": 1, "pass": 0}


def _aggregate_status(case_outcomes: list[str]) -> str:
    if not case_outcomes:
        return "error"
    if all(outcome == "skipped" for outcome in case_outcomes):
        return "skipped"
    worst = max(case_outcomes, key=lambda o: _STATUS_PRECEDENCE.get(o, 3))
    # Skipped cases mixed in with otherwise-passing cases shouldn't
    # downgrade an executed, passing rule -- only fail/error do that.
    return "pass" if worst == "skipped" else worst


def run_rule(rule_path: Path, fixture_dir: Path, hayabusa_available: bool) -> dict[str, Any]:
    testcases_path = find_testcases_file(rule_path)
    if testcases_path is None:
        return {
            "rule": str(rule_path),
            "status": "error",
            "detail": f"no non-empty sibling {rule_path.stem}{TEST_CASE_FILE_SUFFIX} found",
            "cases": [],
        }

    blocks = iter_yaml_blocks(testcases_path)
    if not blocks:
        return {
            "rule": str(rule_path),
            "status": "error",
            "detail": f"no ```yaml execution-test blocks found in {testcases_path.name}",
            "cases": [],
        }

    cases_out: list[dict[str, Any]] = []
    for block in blocks:
        parsed = parse_case(block)
        if parsed.get("parse_error"):
            cases_out.append(
                {
                    "heading": block["heading"],
                    "line": block["line"],
                    "outcome": "error",
                    "detail": parsed["parse_error"],
                }
            )
            continue
        cases_out.append(run_case(parsed, rule_path, fixture_dir, hayabusa_available))

    status = _aggregate_status([c["outcome"] for c in cases_out])
    return {"rule": str(rule_path), "status": status, "cases": cases_out}


def expand_rule_paths(raw_paths: list[str]) -> list[Path]:
    expanded: list[Path] = []
    for raw in raw_paths:
        path = Path(raw)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.yml")))
        else:
            expanded.append(path)
    return expanded


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "rule_paths",
        nargs="+",
        help="One or more Sigma rule .yml files, and/or directories to expand to *.yml",
    )
    parser.add_argument(
        "--fixtures-dir",
        help="Override fixture resolution (default: HAYABUSA_SAMPLE_EVTX_DIR env var, "
        "else vendored tests/fixtures/evtx/)",
    )
    args = parser.parse_args()

    if args.fixtures_dir:
        fixture_dir = Path(args.fixtures_dir).expanduser().resolve()
    else:
        fixture_dir = resolve_fixture_dir()

    try:
        resolve_hayabusa_binary()
        hayabusa_available = True
    except HayabusaNotFoundError:
        hayabusa_available = False

    rule_paths = expand_rule_paths(args.rule_paths)
    rules_out = [run_rule(rule_path, fixture_dir, hayabusa_available) for rule_path in rule_paths]

    statuses = [r["status"] for r in rules_out]
    summary = {
        "total": len(statuses),
        "passed": statuses.count("pass"),
        "failed": statuses.count("fail"),
        "skipped": statuses.count("skipped"),
        "errors": statuses.count("error"),
    }

    print(json.dumps({"rules": rules_out, "summary": summary}, indent=2))

    if summary["errors"]:
        sys.exit(2)
    if summary["failed"]:
        sys.exit(1)
    if summary["skipped"]:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
