"""Detection knowledge base: browsable Sigma rule catalog and ATT&CK tag coverage.

Like get_hayabusa_rules in hayabusa.py, this reads hayabusa's local Sigma rule
YAML files directly instead of shelling out to hayabusa -- hayabusa has no
subcommand that exposes its full rule catalog or ATT&CK coverage, only rules
that actually fired during a scan. ATT&CK technique/tactic data here is
derived entirely from each rule's own `tags:` field (e.g. "attack.t1059.001",
"attack.execution"), not from a bundled MITRE reference dataset, so it always
matches whatever rules are actually installed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml

from .hayabusa import _default_rules_dir, _require_existing_path

MAX_ITEMS_RETURNED = 200

# Sigma's ATT&CK tag convention: "attack.t1059" / "attack.t1059.001" for
# (sub)techniques, "attack.execution" / "attack.credential-access" for
# tactics. Tags like "attack.g0007" (threat actor group) or "attack.s0002"
# (software/tool) contain digits and are intentionally excluded from both.
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_TAG_RE = re.compile(r"^attack\.([a-z][a-z-]*)$", re.IGNORECASE)


def _resolve_rules_dir(rules_dir: str | None) -> Path:
    if rules_dir:
        rules_path = _require_existing_path(rules_dir, label="rules_dir")
    else:
        rules_path = _require_existing_path(str(_default_rules_dir()), label="rules_dir")
    if not rules_path.is_dir():
        raise NotADirectoryError(f"rules_dir is not a directory: {rules_path}")
    return rules_path


def _iter_rule_files(rules_path: Path) -> list[Path]:
    return sorted(
        p for p in rules_path.rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml")
    )


def _parse_rule_file(path: Path, base: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None

    tags = data.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]

    return {
        "id": data.get("id"),
        "title": data.get("title") or "",
        "level": data.get("level"),
        "status": data.get("status"),
        "tags": [str(t) for t in tags],
        "description": data.get("description") or "",
        "path": str(path.relative_to(base)),
    }


def load_rule_catalog(rules_dir: str | None = None) -> tuple[Path, list[dict], int]:
    """Parse every Sigma rule under rules_dir.

    Returns (resolved rules_path, parsed rule records, parse_errors count).
    Malformed rule files are skipped and counted rather than raising, same
    as get_hayabusa_rules.
    """
    rules_path = _resolve_rules_dir(rules_dir)
    records: list[dict] = []
    parse_errors = 0
    for rule_file in _iter_rule_files(rules_path):
        record = _parse_rule_file(rule_file, rules_path)
        if record is None:
            parse_errors += 1
            continue
        records.append(record)
    return rules_path, records, parse_errors


def _technique_ids(tags: list[str]) -> list[str]:
    ids = []
    for tag in tags:
        match = _TECHNIQUE_TAG_RE.match(tag)
        if match:
            ids.append(match.group(1).upper())
    return ids


def _tactic_names(tags: list[str]) -> list[str]:
    names = []
    for tag in tags:
        if _TECHNIQUE_TAG_RE.match(tag):
            continue
        match = _TACTIC_TAG_RE.match(tag)
        if match:
            names.append(match.group(1).lower())
    return names


def rules_index(rules_dir: str | None = None, max_items: int = MAX_ITEMS_RETURNED) -> dict:
    """Browsable rule catalog, grouped by the rule's top two path segments.

    E.g. rules under "sigma/builtin/..." group under "sigma/builtin"; this
    keeps the index to a manageable number of categories instead of one flat
    list of several thousand rules or one entry per top-level directory.
    """
    rules_path, records, parse_errors = load_rule_catalog(rules_dir)

    groups: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        parts = Path(record["path"]).parts
        category = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        groups[category].append(
            {
                "id": record["id"],
                "title": record["title"],
                "level": record["level"],
                "path": record["path"],
            }
        )

    categories = {}
    for category, items in sorted(groups.items()):
        categories[category] = {
            "total_rules": len(items),
            "returned_rules": min(len(items), max_items),
            "truncated": len(items) > max_items,
            "rules": items[:max_items],
        }

    return {
        "rules_dir": str(rules_path),
        "total_rules": len(records),
        "parse_errors": parse_errors,
        "categories": categories,
    }


def get_rule(rule_id: str, rules_dir: str | None = None) -> dict:
    """Full detail for a single rule, looked up by its Sigma `id` field."""
    rules_path, records, _ = load_rule_catalog(rules_dir)
    for record in records:
        if record["id"] == rule_id:
            return record
    raise KeyError(f"No rule found with id {rule_id!r} under {rules_path}")


def list_attack_techniques(rules_dir: str | None = None, max_items: int = MAX_ITEMS_RETURNED) -> dict:
    """ATT&CK technique ID -> detecting rules: detection coverage by technique."""
    rules_path, records, parse_errors = load_rule_catalog(rules_dir)

    coverage: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        for technique_id in _technique_ids(record["tags"]):
            coverage[technique_id].append(
                {"id": record["id"], "title": record["title"], "path": record["path"]}
            )

    techniques = {}
    for technique_id, rules in sorted(coverage.items()):
        techniques[technique_id] = {
            "rule_count": len(rules),
            "returned_rules": min(len(rules), max_items),
            "truncated": len(rules) > max_items,
            "rules": rules[:max_items],
        }

    return {
        "rules_dir": str(rules_path),
        "total_rules_scanned": len(records),
        "parse_errors": parse_errors,
        "total_techniques": len(techniques),
        "techniques": techniques,
    }


def get_attack_technique(
    technique_id: str, rules_dir: str | None = None, max_items: int = MAX_ITEMS_RETURNED
) -> dict:
    """Rules detecting a single ATT&CK technique ID (e.g. "T1059.001")."""
    rules_path, records, _ = load_rule_catalog(rules_dir)
    normalized = technique_id.upper()

    rules = [
        {"id": r["id"], "title": r["title"], "level": r["level"], "path": r["path"]}
        for r in records
        if normalized in _technique_ids(r["tags"])
    ]

    return {
        "rules_dir": str(rules_path),
        "technique_id": normalized,
        "total_rules": len(rules),
        "returned_rules": min(len(rules), max_items),
        "truncated": len(rules) > max_items,
        "rules": rules[:max_items],
    }


def list_attack_tactics(rules_dir: str | None = None, max_items: int = MAX_ITEMS_RETURNED) -> dict:
    """ATT&CK tactic -> detecting rules: detection coverage by tactic."""
    rules_path, records, parse_errors = load_rule_catalog(rules_dir)

    coverage: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        for tactic in _tactic_names(record["tags"]):
            coverage[tactic].append(
                {"id": record["id"], "title": record["title"], "path": record["path"]}
            )

    tactics = {}
    for tactic, rules in sorted(coverage.items()):
        tactics[tactic] = {
            "rule_count": len(rules),
            "returned_rules": min(len(rules), max_items),
            "truncated": len(rules) > max_items,
            "rules": rules[:max_items],
        }

    return {
        "rules_dir": str(rules_path),
        "total_rules_scanned": len(records),
        "parse_errors": parse_errors,
        "total_tactics": len(tactics),
        "tactics": tactics,
    }
