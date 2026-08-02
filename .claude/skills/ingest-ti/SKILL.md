---
name: ingest-ti
description: Use when ingesting threat-intelligence IOC data (native JSON lists, MISP JSON event exports), normalizing indicators to a common schema, or correlating them across sources and against this project's Sigma rule coverage. Enforces the normalized IOC schema and the v1 scope limits below.
---

# Threat Intelligence Ingestion & Correlation

Ingests IOC data from local files, normalizes every indicator to a common schema, then correlates it — across multiple TI sources, against this project's installed Sigma rule coverage, and optionally against a saved Hayabusa scan/timeline result — via two deterministic scripts. This is the backing skill for the `/ingest-ti` command (`.claude/commands/ingest-ti.md`).

## Normalized IOC schema

Every indicator, regardless of source format, is normalized to exactly these fields (all keys always present; a value may be `null`, but the key isn't dropped):

```json
{
  "type": "ip",
  "value": "1.2.3.4",
  "confidence": 0.8,
  "source": "native:watchlist",
  "first_seen": "2026-01-01T00:00:00Z",
  "attack_technique": "T1071.001",
  "notes": "category=Network activity; comment=C2 IP"
}
```

`type` is a closed set: `ip`, `domain`, `hash`, `url`, `other`. An entry with an unrecognized `type` is coerced to `other` (not dropped); an entry missing `value` entirely is skipped (it can't be correlated on anything).

## How to apply

1. **Ingest each source file separately** with `ingest_ti.py` — one file in, one normalized JSON report out. Never hand-parse a TI file's JSON yourself; the format-detection and normalization logic here is deterministic and already handles both supported formats' edge cases (MISP type mapping, epoch timestamp conversion, missing-field defaulting).
2. **Correlate normalized reports together** with `correlate_ti.py` — takes 1+ of `ingest_ti.py`'s output files, merges/dedupes IOCs sharing a `(type, value)` key across sources, and checks every referenced ATT&CK technique against this project's installed Sigma rules via `analyze_coverage`/`suggest_rule` (`mcp_hayabusa.knowledge` — the same functions backing this project's `analyze_coverage`/`suggest_rule` MCP tools, not reimplemented here).
3. **Optionally correlate against local evidence** by passing `--hayabusa-result <path>` to `correlate_ti.py`, pointing at a JSON file already saved to disk from a prior Hayabusa MCP tool call (`scan_evtx`, `hayabusa_csv_timeline`, `hayabusa_json_timeline`, etc.) — each merged indicator's value is then substring-matched against that file's raw text.

## Usage

```bash
python .claude/skills/ingest-ti/scripts/ingest_ti.py path/to/misp_export.json > /tmp/norm1.json
python .claude/skills/ingest-ti/scripts/ingest_ti.py path/to/watchlist.json > /tmp/norm2.json
python .claude/skills/ingest-ti/scripts/correlate_ti.py /tmp/norm1.json /tmp/norm2.json \
    --hayabusa-result artifacts/scan_win-client01.json
```

**`ingest_ti.py <input.json> [--format {auto,native,misp}] [--source-label LABEL]`**
- `--format` forces the parser instead of auto-detecting (auto-detection: a MISP `{Event:{Attribute:[...]}}` export vs. a native `{indicators:[...]}` / bare `[...]` list).
- `--source-label` overrides the derived `source` value for every indicator from that file.
- Exit codes: `0` every indicator normalized cleanly; `1` one or more indicators were skipped or had a value coerced (report still printed in full — a deliberate choice, not a fatal error, since a partially-usable file is more useful than none); `2` usage/parse error (file missing, invalid JSON, unrecognized top-level shape).

**`correlate_ti.py <normalized.json | dir> [...] [--hayabusa-result PATH] [--rules-dir DIR]`**
- Positional args accept `ingest_ti.py` report files and/or directories (directories expand to `*.json`).
- `--rules-dir` overrides the Sigma rules directory passed through to `analyze_coverage`/`suggest_rule` (default: hayabusa binary's own `rules/` dir).
- Exit codes: `0` clean run, every referenced technique covered; `1` a soft problem — a malformed indicator entry was skipped and/or at least one referenced technique has no installed rule coverage; `2` usage/parse error (missing/malformed input file, wrong top-level shape, a `--hayabusa-result`/`--rules-dir` path that doesn't exist).

## Explicitly out of scope for v1

- No STIX/TAXII parsing, no live TI feed/API integrations (MISP API, OTX, abuse.ch, etc.) — file-based native and MISP JSON export only.
- No parsing of existing `investigations/*.md` notes as an IOC/correlation source.
- No MISP Galaxy/Tag-based ATT&CK technique extraction — MISP-derived indicators always have `attack_technique: null`.
- MISP `confidence` is a coarse `to_ids`-based heuristic (`0.75`/`0.5`), not a faithful translation of MISP's own confidence/warninglist semantics.
- Cross-source dedup uses an exact, case-insensitive `(type, value)` key — no defanged-IOC normalization (`hxxp://`, `1[.]2[.]3[.]4`) and no CIDR/subdomain-aware IP/domain matching.
- Evidence correlation against a `--hayabusa-result` file is a plain case-insensitive textual substring match on the raw file content, not a structural/field-aware match — a documented, accepted source of possible false positives (values under 3 characters are skipped to reduce noise, but longer generic-looking values can still match spuriously).
- No bundled MITRE ATT&CK reference dataset (consistent with `knowledge.py`'s existing scope decision — see `CLAUDE.md`) — technique coverage here is always relative to the installed rule set, never a full-ATT&CK-matrix gap analysis.

Don't silently expand any of the above — if a task needs it, raise it as a scope decision first rather than quietly bolting it on.

## References

- `references/example-native-iocs.json` — a well-formed native IOC list to follow.
- `references/example-misp-event.json` — a well-formed MISP event export to follow.
