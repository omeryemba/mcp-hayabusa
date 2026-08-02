#!/usr/bin/env python3
"""Merge, deduplicate, and correlate normalized threat-intel IOC reports.

Usage:
    python correlate_ti.py <normalized.json | dir> [...] [--hayabusa-result PATH] [--rules-dir DIR]

Takes one or more JSON reports produced by ingest_ti.py (files and/or
directories, directories expanded to *.json), merges indicators that share
the same (type, value) key across all of them, and checks every ATT&CK
technique referenced by a merged indicator against this project's installed
Sigma rule coverage via analyze_coverage()/suggest_rule()
(mcp_hayabusa.knowledge) -- the same functions backing this project's
analyze_coverage/suggest_rule MCP tools, reused here rather than
reimplemented.

If --hayabusa-result is given, it's treated as a JSON file already saved to
disk from a prior Hayabusa MCP tool call (e.g. scan_evtx, csv_timeline) --
each merged indicator's value is matched against that file's raw text with a
case-insensitive substring search (values shorter than 3 characters are
skipped to reduce noise) and flagged as observed_in_evidence.

See ../SKILL.md's "Explicitly out of scope for v1" for the documented
limitations of the dedup key and evidence-matching approach.

Prints a JSON correlation report to stdout. Exit codes:
    0 - clean run: no issues, every referenced ATT&CK technique is covered
        by at least one installed Sigma rule
    1 - a soft problem: a malformed indicator entry was skipped, and/or at
        least one referenced technique has no installed rule coverage
    2 - a usage/parse error: missing/malformed input file, wrong top-level
        shape, or a specified --hayabusa-result/--rules-dir path that
        doesn't exist
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp_hayabusa.config import HayabusaNotFoundError
from mcp_hayabusa.knowledge import analyze_coverage, suggest_rule

MIN_EVIDENCE_MATCH_LEN = 3


def fail(message: str) -> None:
    print(json.dumps({"valid": False, "issues": [message]}, indent=2))
    sys.exit(2)


def expand_ioc_paths(raw_paths: list[str]) -> list[Path]:
    expanded: list[Path] = []
    for raw in raw_paths:
        path = Path(raw)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.json")))
        else:
            expanded.append(path)
    return expanded


def load_normalized_file(path: Path, issues: list[str]) -> tuple[dict[str, Any], list[dict]]:
    """Load one ingest_ti.py report file. A file not shaped like one is a usage error."""
    if not path.is_file():
        fail(f"File not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        fail(f"JSON parse error in {path}: {exc}")

    if not isinstance(data, dict) or not isinstance(data.get("indicators"), list):
        fail(f"{path} does not look like an ingest_ti.py report (missing top-level 'indicators' list).")

    valid_indicators = []
    for i, entry in enumerate(data["indicators"]):
        if not isinstance(entry, dict) or not entry.get("type") or not entry.get("value"):
            issues.append(f"{path}: indicator[{i}] missing 'type'/'value', skipped.")
            continue
        valid_indicators.append(entry)

    source_summary = {
        "file": str(path),
        "format_detected": data.get("format_detected"),
        "indicator_count": len(valid_indicators),
    }
    return source_summary, valid_indicators


def merge_indicators(all_indicators: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for entry in all_indicators:
        key = (str(entry.get("type")).lower(), str(entry.get("value")).strip().lower())
        groups.setdefault(key, []).append(entry)

    merged: list[dict] = []
    for members in groups.values():
        confidences = [
            m["confidence"] for m in members if isinstance(m.get("confidence"), (int, float))
        ]
        sources = sorted({m["source"] for m in members if m.get("source")})
        first_seens = sorted(m["first_seen"] for m in members if m.get("first_seen"))
        technique = next((m["attack_technique"] for m in members if m.get("attack_technique")), None)
        notes = list(dict.fromkeys(m["notes"] for m in members if m.get("notes")))

        merged.append(
            {
                "type": str(members[0].get("type")).lower(),
                "value": members[0]["value"],
                "confidence": max(confidences) if confidences else 0.0,
                "source": sources,
                "first_seen": first_seens[0] if first_seens else None,
                "attack_technique": technique,
                "notes": "; ".join(notes) if notes else None,
                "merged_from": len(members),
            }
        )

    return merged


def correlate_evidence(merged: list[dict], evidence_text: str | None) -> None:
    """Mutate each merged indicator in place, adding observed_in_evidence/evidence_match_count."""
    for entry in merged:
        if evidence_text is None or len(entry["value"]) < MIN_EVIDENCE_MATCH_LEN:
            entry["observed_in_evidence"] = False
            entry["evidence_match_count"] = 0
            continue
        count = evidence_text.lower().count(entry["value"].lower())
        entry["observed_in_evidence"] = count > 0
        entry["evidence_match_count"] = count


def build_technique_coverage(merged: list[dict], rules_dir: str | None) -> list[dict]:
    technique_ids = sorted({m["attack_technique"] for m in merged if m.get("attack_technique")})

    coverage: list[dict] = []
    for tid in technique_ids:
        indicators_for_technique = [m for m in merged if m.get("attack_technique") == tid]
        coverage_result = analyze_coverage(technique_id=tid, rules_dir=rules_dir)

        notes_for_query = "; ".join(
            dict.fromkeys(m["notes"] for m in indicators_for_technique if m.get("notes"))
        )
        query = notes_for_query or tid
        suggestion_result = suggest_rule(query=query, technique_id=tid, rules_dir=rules_dir)

        coverage.append(
            {
                "technique_id": coverage_result["technique_id"],
                "mitre_url": coverage_result["mitre_url"],
                "covered": coverage_result["covered"],
                "rule_count": coverage_result["rule_count"],
                "indicator_count": len(indicators_for_technique),
                "suggested_rules": suggestion_result["suggestions"],
            }
        )

    return coverage


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "normalized_paths",
        nargs="+",
        help="One or more ingest_ti.py report .json files, and/or directories to expand to *.json",
    )
    parser.add_argument(
        "--hayabusa-result",
        help="Path to a saved Hayabusa MCP tool result (JSON) to correlate IOC values against",
    )
    parser.add_argument(
        "--rules-dir",
        help="Override the Sigma rules directory (default: hayabusa binary's own rules/ dir)",
    )
    args = parser.parse_args()

    issues: list[str] = []
    paths = expand_ioc_paths(args.normalized_paths)

    sources = []
    all_indicators: list[dict] = []
    for path in paths:
        source_summary, valid_indicators = load_normalized_file(path, issues)
        sources.append(source_summary)
        all_indicators.extend(valid_indicators)

    evidence_text = None
    hayabusa_result_file = None
    if args.hayabusa_result:
        evidence_path = Path(args.hayabusa_result)
        if not evidence_path.is_file():
            fail(f"--hayabusa-result path not found: {evidence_path}")
        evidence_text = evidence_path.read_text(encoding="utf-8", errors="replace")
        hayabusa_result_file = str(evidence_path)

    merged = merge_indicators(all_indicators)
    correlate_evidence(merged, evidence_text)

    try:
        technique_coverage = build_technique_coverage(merged, args.rules_dir)
    except (FileNotFoundError, NotADirectoryError, HayabusaNotFoundError) as exc:
        fail(f"Could not resolve Sigma rules directory: {exc}")

    summary = {
        "total_indicators_in": len(all_indicators),
        "total_indicators_after_merge": len(merged),
        "merged_groups": sum(1 for m in merged if m["merged_from"] > 1),
        "techniques_referenced": len(technique_coverage),
        "techniques_covered": sum(1 for t in technique_coverage if t["covered"]),
        "techniques_uncovered": sum(1 for t in technique_coverage if not t["covered"]),
        "observed_in_evidence": sum(1 for m in merged if m.get("observed_in_evidence")),
    }

    result = {
        "sources": sources,
        "hayabusa_result_file": hayabusa_result_file,
        "rules_dir": args.rules_dir,
        "summary": summary,
        "indicators": merged,
        "technique_coverage": technique_coverage,
        "issues": issues,
    }

    print(json.dumps(result, indent=2))

    has_uncovered = any(not t["covered"] for t in technique_coverage)
    sys.exit(1 if (issues or has_uncovered) else 0)


if __name__ == "__main__":
    main()
