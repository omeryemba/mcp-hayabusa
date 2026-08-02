---
name: ingest-ti
description: Ingest threat-intelligence IOC data from local files, normalize it, and correlate it across sources, against Sigma rule coverage, and optionally against local Hayabusa evidence
---

# Workflow

You are ingesting threat-intelligence indicators (IOCs) and correlating them with this project's detection coverage, following the `ingest-ti` skill (`.claude/skills/ingest-ti/SKILL.md`).

## Input

Arguments: $ARGUMENTS

Parse as whitespace-separated tokens:

1. **IOC source file(s)** (required, one or more) — every token that is *not* prefixed `evidence:`. If none are given, stop and ask the user for at least one IOC source file before doing anything else.
2. **Evidence file** (optional) — a token prefixed `evidence:<path>`, a path to a JSON file already saved to disk containing the output of a prior Hayabusa MCP tool call (`scan_evtx`, `hayabusa_csv_timeline`, `hayabusa_json_timeline`, etc.) from earlier in the session. If more than one `evidence:` token is given, use the last one and note that the earlier one(s) were overridden.

Example:

```
/ingest-ti intel/misp_export.json intel/watchlist.json evidence:artifacts/scan_win-client01.json
```

## Steps

1. Confirm at least one IOC source file was supplied; stop and ask if not. Confirm every listed IOC source file exists before running anything; if any don't, tell the user exactly which ones and stop rather than silently dropping them.

2. For each IOC source file, run:
   ```
   python .claude/skills/ingest-ti/scripts/ingest_ti.py <file>
   ```
   Save each run's stdout to a scratch JSON file (these are intermediate working files, not part of the final saved artifact — don't put them under `investigations/`). If a run exits `2`, stop and report the parse failure for that file rather than silently skipping it. If a run exits `1`, keep going but carry its `issues` list forward into the note's Limitations section.

3. If an `evidence:` file was given, confirm it exists. If it doesn't, tell the user and continue without evidence correlation rather than fabricating matches — the same "say so explicitly, don't silently skip" rule `/investigate-endpoint` uses for a missing SIEM integration.

4. Run:
   ```
   python .claude/skills/ingest-ti/scripts/correlate_ti.py <scratch1.json> [<scratch2.json> ...] [--hayabusa-result <evidence-file>]
   ```
   Capture its JSON output. If it exits `2`, stop and report the failure — don't fabricate a correlation result.

5. Build the investigation note from `correlate_ti.py`'s output (see Output below).

6. Save under `investigations/ti_<slug>_<YYYY-MM-DD>.md`, creating the directory if it doesn't exist, where `<slug>` is the underscore-joined basenames (no extension) of up to the first 3 IOC source files. Report the saved path back to the user.

## Output

Start the file with an Obsidian frontmatter block:

```yaml
---
tags: [threat-intel, ioc-ingest]
sources: [<file1>, <file2>, ...]
date: <YYYY-MM-DD>
aliases: [<slug>]
---
```

Followed by the report body:

# Threat Intelligence Ingest: <slug>

## Sources

| File | Format | Indicators | Issues |
|---|---|---|---|

## Indicator Summary

| Type | Value | Confidence | Source(s) | First Seen | ATT&CK | Observed in Evidence |
|---|---|---|---|---|---|---|

## ATT&CK Technique Correlation

| Technique | Covered | Rule Count | Indicators | Suggested Rules |
|---|---|---|---|---|

Reference each technique as a wikilink (e.g. `[[T1071.001]]`) so Obsidian's graph view and backlinks pick it up.

## Evidence Correlation

(If no evidence file was supplied: "No local evidence file supplied — evidence correlation skipped.")

| Value | Evidence Matches |
|---|---|

## Limitations

- No STIX/TAXII or live TI feed API support in v1 — file-based native/MISP JSON only.
- Existing `investigations/*.md` notes are not parsed or correlated against.
- Cross-source dedup key is case-insensitive exact `(type, value)` match only.
- Evidence correlation is a plain case-insensitive textual substring match against the hayabusa-result file's raw content, not structural field matching.
- (any per-file issues surfaced by `ingest_ti.py`/`correlate_ti.py`)

## Recommendations

- Prioritize indicators with confirmed evidence matches.
- Close coverage gaps for uncovered techniques.
- Treat single-source / low-confidence indicators with caution before acting on them.
