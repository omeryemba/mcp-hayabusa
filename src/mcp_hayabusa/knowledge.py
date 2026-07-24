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
MAX_SUGGESTIONS_RETURNED = 10

# Sigma's ATT&CK tag convention: "attack.t1059" / "attack.t1059.001" for
# (sub)techniques, "attack.execution" / "attack.credential-access" for
# tactics. Tags like "attack.g0007" (threat actor group) or "attack.s0002"
# (software/tool) contain digits and are intentionally excluded from both.
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TACTIC_TAG_RE = re.compile(r"^attack\.([a-z][a-z-]*)$", re.IGNORECASE)

# Human-readable names for the 14 Enterprise ATT&CK tactics. Hand-maintained
# here rather than sourced from a bundled dataset -- these have been stable
# across ATT&CK versions, unlike the much larger and more volatile technique
# list, so the maintenance cost of keeping this in sync is low. Technique IDs
# are deliberately *not* similarly enriched with names (see CLAUDE.md): that
# would require bundling real ATT&CK content, which this module intentionally
# avoids so its output never goes stale against upstream ATT&CK or needs a
# licensing note.
_TACTIC_DISPLAY_NAMES: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


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


def _tactic_display_name(tactic: str) -> str:
    """Human-readable name for a tactic slug, e.g. "credential-access" -> "Credential Access".

    Falls back to title-casing the slug for anything not in
    _TACTIC_DISPLAY_NAMES, so an unrecognized tactic tag still gets a
    reasonable label instead of disappearing or raising.
    """
    return _TACTIC_DISPLAY_NAMES.get(tactic, tactic.replace("-", " ").title())


def _mitre_url(technique_id: str) -> str:
    """MITRE ATT&CK technique page URL, computed from the ID -- no lookup needed.

    E.g. "T1059" -> ".../techniques/T1059/", "T1059.001" -> ".../techniques/T1059/001/".
    """
    normalized = technique_id.upper()
    base, _, sub = normalized.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{base}/"


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
            "mitre_url": _mitre_url(technique_id),
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
        "mitre_url": _mitre_url(normalized),
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
            "display_name": _tactic_display_name(tactic),
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


_COVERAGE_SCOPE_NOTE = (
    "Coverage reflects only techniques/tactics referenced by tags on rules "
    "present in this rule dataset (rules_dir). It is not compared against "
    "the full MITRE ATT&CK technique matrix -- no such reference dataset is "
    "bundled here -- so this cannot report techniques with zero rules across "
    "all of ATT&CK, only the relative distribution across what is actually "
    "installed."
)


def analyze_coverage(
    rules_dir: str | None = None,
    technique_id: str | None = None,
    max_items: int = MAX_ITEMS_RETURNED,
) -> dict:
    """Detection coverage analysis over the installed rule set's ATT&CK tags.

    With no technique_id, returns an overall breakdown: how many rules cover
    each technique/tactic referenced anywhere in the rule set, sorted
    ascending by rule_count (weakest-covered first) so the least-covered
    techniques/tactics are easy to spot. With technique_id, returns a
    focused answer for that one technique instead.

    IMPORTANT: this is coverage over the *installed rule set*, not a gap
    analysis against ATT&CK itself -- see coverage_scope in the response.

    Args:
        technique_id: Optional single ATT&CK technique ID (e.g.
            "T1059.001") to report focused coverage for. An id with no
            installed rules returns rule_count 0 and covered=False rather
            than raising -- "not covered" is a normal, expected answer for
            a coverage query, not an error (consistent with
            get_attack_technique's handling of an unmatched id).
        max_items: Maximum number of techniques/tactics to include in the
            overall breakdown lists (default 200). Ignored when
            technique_id is given.
    """
    rules_path, records, parse_errors = load_rule_catalog(rules_dir)

    technique_counts: dict[str, int] = defaultdict(int)
    tactic_counts: dict[str, int] = defaultdict(int)
    for record in records:
        for tid in _technique_ids(record["tags"]):
            technique_counts[tid] += 1
        for tname in _tactic_names(record["tags"]):
            tactic_counts[tname] += 1

    result: dict = {
        "rules_dir": str(rules_path),
        "coverage_scope": _COVERAGE_SCOPE_NOTE,
        "total_rules_scanned": len(records),
        "parse_errors": parse_errors,
        "total_techniques_covered": len(technique_counts),
        "total_tactics_covered": len(tactic_counts),
    }

    if technique_id is not None:
        normalized = technique_id.upper()
        rule_count = technique_counts.get(normalized, 0)
        result["technique_id"] = normalized
        result["mitre_url"] = _mitre_url(normalized)
        result["rule_count"] = rule_count
        result["covered"] = rule_count > 0
        return result

    techniques_sorted = sorted(technique_counts.items(), key=lambda kv: (kv[1], kv[0]))
    tactics_sorted = sorted(tactic_counts.items(), key=lambda kv: (kv[1], kv[0]))

    result["techniques_by_coverage"] = [
        {"technique_id": tid, "mitre_url": _mitre_url(tid), "rule_count": count}
        for tid, count in techniques_sorted[:max_items]
    ]
    result["techniques_truncated"] = len(techniques_sorted) > max_items
    result["tactics_by_coverage"] = [
        {"tactic": name, "display_name": _tactic_display_name(name), "rule_count": count}
        for name, count in tactics_sorted[:max_items]
    ]
    result["tactics_truncated"] = len(tactics_sorted) > max_items

    return result


def suggest_rule(
    query: str,
    technique_id: str | None = None,
    max_suggestions: int = MAX_SUGGESTIONS_RETURNED,
    rules_dir: str | None = None,
) -> dict:
    """Rank installed rules by relevance to a free-text query.

    Unlike get_hayabusa_rules (exact case-insensitive substring match,
    returns every match up to max_rules), this scores each rule by how many
    of query's whitespace-separated terms it matches -- weighting a title
    match above a tags match above a description-only match -- and returns
    only the top max_suggestions candidates. Intended for "is there already
    a rule for X" / "which existing rule is closest to Y"; it finds and
    ranks *existing* rules, it does not write or generate new Sigma rules.

    Args:
        query: Free-text description of the detection you're looking for,
            e.g. "mimikatz credential dumping". Required, non-empty.
        technique_id: Optional ATT&CK technique ID (e.g. "T1003.001") to
            restrict candidates to rules already tagged with that technique
            before ranking.
        max_suggestions: Maximum number of ranked candidates to return
            (default 10).
    """
    if not query or not query.strip():
        raise ValueError("query must be a non-empty string")

    rules_path, records, parse_errors = load_rule_catalog(rules_dir)

    normalized_technique = technique_id.upper() if technique_id else None
    if normalized_technique is not None:
        records = [r for r in records if normalized_technique in _technique_ids(r["tags"])]

    terms = [t.lower() for t in query.split() if t]

    scored: list[tuple[int, dict]] = []
    for record in records:
        title_lower = record["title"].lower()
        description_lower = record["description"].lower()
        tags_lower = " ".join(record["tags"]).lower()

        score = 0
        for term in terms:
            if term in title_lower:
                score += 3
            if term in tags_lower:
                score += 2
            if term in description_lower:
                score += 1
        if score > 0:
            scored.append((score, record))

    scored.sort(key=lambda pair: (-pair[0], pair[1]["title"]))

    suggestions = [
        {
            "id": record["id"],
            "title": record["title"],
            "level": record["level"],
            "path": record["path"],
            "score": score,
        }
        for score, record in scored[:max_suggestions]
    ]

    return {
        "rules_dir": str(rules_path),
        "query": query,
        "technique_id": normalized_technique,
        "candidates_considered": len(records),
        "parse_errors": parse_errors,
        "total_matches": len(scored),
        "returned_suggestions": len(suggestions),
        "truncated": len(scored) > len(suggestions),
        "suggestions": suggestions,
    }
