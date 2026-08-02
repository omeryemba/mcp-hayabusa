#!/usr/bin/env python3
"""Normalize a threat-intel IOC file into this project's common IOC schema.

Usage:
    python ingest_ti.py <path-to-ioc-file.json> [--format {auto,native,misp}] [--source-label LABEL]

Supported input formats (see ../SKILL.md for the full schema this enforces):
  - native: a bare JSON array of indicator objects, or {"indicators": [...]}.
  - misp: a MISP JSON event export, {"Event": {"Attribute": [...], ...}}.

Every recognized indicator is normalized to a fixed schema:
    {type, value, confidence, source, first_seen, attack_technique, notes}
'type' is one of: ip, domain, hash, url, other. An entry missing 'value' is
skipped; an entry with an unrecognized 'type' is coerced to 'other' rather
than dropped.

No STIX/TAXII or live TI feed API support -- file-based native/MISP JSON
only. See ../SKILL.md's "Explicitly out of scope for v1" for the full list
of documented v1 limitations (MISP confidence heuristic, no Galaxy/Tag
technique extraction, etc.).

Prints a JSON normalization report to stdout. Exit codes:
    0 - every indicator normalized cleanly
    1 - one or more indicators were skipped or had a value coerced (the
        report is still printed in full -- a partially-usable file is more
        useful than none)
    2 - a usage/parse error: file missing, invalid JSON, or an unrecognized
        top-level shape
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_TYPES = {"ip", "domain", "hash", "url", "other"}
DEFAULT_CONFIDENCE = 0.5
MISP_TO_IDS_CONFIDENCE = 0.75

_MISP_TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "ssdeep": "hash",
    "imphash": "hash",
    "authentihash": "hash",
    "url": "url",
    "uri": "url",
}


def detect_format(data: Any) -> str | None:
    """Sniff whether parsed JSON is a MISP event export or a native IOC list."""
    if isinstance(data, list):
        return "native"
    if isinstance(data, dict):
        event = data.get("Event")
        if isinstance(event, dict) and isinstance(event.get("Attribute"), list):
            return "misp"
        if isinstance(data.get("indicators"), list):
            return "native"
    return None


def _epoch_to_iso(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def normalize_native(
    data: Any, source_label: str | None, file_stem: str, issues: list[str]
) -> tuple[list[dict], int]:
    raw_indicators = data if isinstance(data, list) else data.get("indicators", [])
    default_source = source_label or f"native:{file_stem}"

    normalized: list[dict] = []
    for i, entry in enumerate(raw_indicators):
        if not isinstance(entry, dict):
            issues.append(f"indicator[{i}]: not a JSON object, skipped.")
            continue

        value = entry.get("value")
        if not isinstance(value, str) or not value.strip():
            issues.append(f"indicator[{i}]: missing or empty 'value', skipped.")
            continue

        raw_type = entry.get("type")
        type_ = raw_type.lower() if isinstance(raw_type, str) else ""
        if type_ not in VALID_TYPES:
            issues.append(f"indicator[{i}]: unrecognized type {raw_type!r}, coerced to 'other'.")
            type_ = "other"

        confidence = entry.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            confidence = DEFAULT_CONFIDENCE

        normalized.append(
            {
                "type": type_,
                "value": value.strip(),
                "confidence": float(confidence),
                "source": entry.get("source") or default_source,
                "first_seen": entry.get("first_seen"),
                "attack_technique": entry.get("attack_technique"),
                "notes": entry.get("notes"),
            }
        )

    return normalized, len(raw_indicators)


def normalize_misp(data: dict, source_label: str | None, issues: list[str]) -> tuple[list[dict], int]:
    event = data.get("Event") or {}
    attributes = event.get("Attribute") or []
    default_source = source_label or f"MISP:{event.get('info') or event.get('uuid') or 'unknown-event'}"

    normalized: list[dict] = []
    for i, attr in enumerate(attributes):
        if not isinstance(attr, dict):
            issues.append(f"Attribute[{i}]: not a JSON object, skipped.")
            continue

        value = attr.get("value")
        if not isinstance(value, str) or not value.strip():
            issues.append(f"Attribute[{i}]: missing or empty 'value', skipped.")
            continue

        raw_type = attr.get("type")
        type_ = _MISP_TYPE_MAP.get(raw_type, "other") if isinstance(raw_type, str) else "other"
        if isinstance(raw_type, str) and raw_type not in _MISP_TYPE_MAP:
            issues.append(f"Attribute[{i}]: unmapped MISP type {raw_type!r}, coerced to 'other'.")

        confidence = MISP_TO_IDS_CONFIDENCE if attr.get("to_ids") else DEFAULT_CONFIDENCE

        first_seen = attr.get("first_seen")
        if not first_seen:
            timestamp = attr.get("timestamp")
            if isinstance(timestamp, str) and timestamp.lstrip("-").isdigit():
                first_seen = _epoch_to_iso(int(timestamp))
            elif isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
                first_seen = _epoch_to_iso(timestamp)
            else:
                first_seen = event.get("date")

        category = attr.get("category")
        comment = attr.get("comment")
        notes_parts = [
            f"category={category}" if category else None,
            f"comment={comment}" if comment else None,
        ]
        notes = "; ".join(p for p in notes_parts if p) or None

        normalized.append(
            {
                "type": type_,
                "value": value.strip(),
                "confidence": confidence,
                "source": default_source,
                "first_seen": first_seen,
                "attack_technique": None,
                "notes": notes,
            }
        )

    return normalized, len(attributes)


def fail(file_path: Path, message: str) -> None:
    print(json.dumps({"file": str(file_path), "valid": False, "issues": [message]}, indent=2))
    sys.exit(2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("input_path", help="Path to the IOC file to normalize (JSON)")
    parser.add_argument(
        "--format",
        choices=["auto", "native", "misp"],
        default="auto",
        help="Force the input format instead of auto-detecting it (default: auto)",
    )
    parser.add_argument(
        "--source-label",
        help="Override the derived 'source' value for every indicator from this file",
    )
    args = parser.parse_args()

    file_path = Path(args.input_path)

    if not file_path.is_file():
        fail(file_path, f"File not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        fail(file_path, f"JSON parse error: {exc}")

    event = data.get("Event") if isinstance(data, dict) else None
    is_misp_shaped = isinstance(event, dict) and isinstance(event.get("Attribute"), list)
    is_native_shaped = isinstance(data, list) or (
        isinstance(data, dict) and isinstance(data.get("indicators"), list)
    )

    if args.format == "misp":
        if not is_misp_shaped:
            fail(
                file_path,
                "Forced --format misp but input is not a MISP {Event:{Attribute:[...]}} export.",
            )
        format_used = "misp"
    elif args.format == "native":
        if not is_native_shaped:
            fail(
                file_path,
                "Forced --format native but input is not a bare [...] or {indicators:[...]}.",
            )
        format_used = "native"
    else:
        detected = detect_format(data)
        if detected is None:
            fail(
                file_path,
                "Unrecognized input format: expected a MISP {Event:{Attribute:[...]}} "
                "export or a native {indicators:[...]} / bare [...] IOC list.",
            )
        format_used = detected

    issues: list[str] = []
    if format_used == "misp":
        indicators, total = normalize_misp(data, args.source_label, issues)
    else:
        indicators, total = normalize_native(data, args.source_label, file_path.stem, issues)

    result = {
        "file": str(file_path),
        "format_detected": format_used,
        "source_label": args.source_label,
        "valid": not issues,
        "checks": {
            "format_detection": {"passed": True, "detail": format_used},
            "indicator_normalization": {
                "passed": not issues,
                "total": total,
                "normalized": len(indicators),
                "skipped": total - len(indicators),
            },
        },
        "issues": issues,
        "indicators": indicators,
    }

    print(json.dumps(result, indent=2))
    sys.exit(0 if not issues else 1)


if __name__ == "__main__":
    main()
