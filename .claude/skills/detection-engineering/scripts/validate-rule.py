#!/usr/bin/env python3
"""Validate a Sigma rule against this project's detection-engineering standards.

Usage:
    python validate-rule.py <path-to-rule.yml>

Checks performed (see ../SKILL.md for the full standards this enforces):
  1. At least one ATT&CK technique tag in 'attack.tXXXX' / 'attack.tXXXX.XXX' format.
  2. 'level' is one of: low, medium, high, critical.
  3. 'falsepositives' exists and lists at least one real (non-placeholder) condition.
  4. At least one test case is documented as a sibling '<rule-stem>.testcases.md'
     file next to the rule (e.g. 'my_rule.yml' -> 'my_rule.testcases.md').

Prints a JSON validation report to stdout and exits 0 if the rule passes every
check, 1 if any check fails, 2 on a usage/parse error (file missing, bad YAML,
not a mapping).
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

VALID_LEVELS = {"low", "medium", "high", "critical"}
ATTACK_TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TEST_CASE_FILE_SUFFIX = ".testcases.md"


def check_attack_tags(rule: dict, issues: list) -> dict:
    raw_tags = rule.get("tags") or []
    tags = raw_tags if isinstance(raw_tags, list) else [raw_tags]
    tags = [t for t in tags if isinstance(t, str)]

    matched = [t for t in tags if ATTACK_TECHNIQUE_TAG_RE.match(t)]
    passed = bool(matched)
    if not passed:
        issues.append(
            "No ATT&CK technique tag found (expected a tag like 'attack.t1003.001' "
            "in the 'tags' field)."
        )

    for t in tags:
        if t not in matched and ATTACK_TECHNIQUE_TAG_RE.match(t.lower()):
            issues.append(
                f"Tag '{t}' looks like an ATT&CK technique tag but isn't lowercase "
                f"(expected '{t.lower()}')."
            )

    return {"passed": passed, "found": matched}


def check_severity_level(rule: dict, issues: list) -> dict:
    level = rule.get("level")
    is_str = isinstance(level, str)
    valid_value = is_str and level.lower() in VALID_LEVELS

    if not valid_value:
        issues.append(f"'level' must be one of {sorted(VALID_LEVELS)}, found: {level!r}.")
    elif level != level.lower():
        issues.append(f"'level' value '{level}' should be lowercase ('{level.lower()}').")

    return {"passed": valid_value and level == level.lower() if is_str else False, "value": level}


def check_falsepositives(rule: dict, issues: list) -> dict:
    fps = rule.get("falsepositives")
    fps_list = fps if isinstance(fps, list) else ([fps] if fps else [])
    real = [
        fp for fp in fps_list
        if isinstance(fp, str) and fp.strip() and fp.strip().lower() != "unknown"
    ]
    passed = bool(real)

    if fps is None:
        issues.append("'falsepositives' field is missing.")
    elif not fps_list:
        issues.append("'falsepositives' is empty.")
    elif not real:
        issues.append(
            "'falsepositives' only contains a placeholder value like 'Unknown'; "
            "document realistic false-positive conditions."
        )

    return {"passed": passed, "value": fps}


def find_test_case(rule_path: Path):
    candidate = rule_path.with_name(f"{rule_path.stem}{TEST_CASE_FILE_SUFFIX}")
    if candidate.is_file() and candidate.stat().st_size > 0:
        return True, f"sibling file '{candidate.name}'"
    return False, None


def check_test_case(rule_path: Path, issues: list) -> dict:
    found, detail = find_test_case(rule_path)
    if not found:
        expected = f"{rule_path.stem}{TEST_CASE_FILE_SUFFIX}"
        issues.append(
            f"No test case found: expected a sibling file named '{expected}' "
            f"next to '{rule_path.name}'."
        )
    return {"passed": found, "detail": detail}


def fail(rule_path: Path, message: str) -> None:
    print(json.dumps({"file": str(rule_path), "valid": False, "issues": [message]}, indent=2))
    sys.exit(2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule_path", help="Path to the Sigma rule YAML file to validate")
    args = parser.parse_args()

    rule_path = Path(args.rule_path)

    if not rule_path.is_file():
        fail(rule_path, f"File not found: {rule_path}")

    try:
        with rule_path.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        fail(rule_path, f"YAML parse error: {exc}")

    if not isinstance(rule, dict):
        fail(rule_path, "Rule file does not contain a YAML mapping at the top level.")

    issues: list = []
    checks = {
        "attack_tags": check_attack_tags(rule, issues),
        "severity_level": check_severity_level(rule, issues),
        "falsepositives": check_falsepositives(rule, issues),
        "test_case": check_test_case(rule_path, issues),
    }

    valid = not issues
    result = {
        "file": str(rule_path),
        "valid": valid,
        "checks": checks,
        "issues": issues,
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
