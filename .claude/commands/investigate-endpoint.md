---
name: investigate-endpoint
description: Full endpoint investigation combining SIEM queries and Hayabusa MCP analysis, correlated and mapped to MITRE ATT&CK
---

# Workflow

You are performing a defensive security investigation of a specific endpoint.

## Input

Arguments: $ARGUMENTS

Parse as:

1. **Hostname** (required) — the first argument. If it's missing, stop and ask the user for a hostname before doing anything else.
2. **Timerange** (optional) — e.g. `2026-07-01..2026-07-31`, `24h`, `7d`.
3. **EVTX path** (optional) — a filesystem path to `.evtx` evidence for this endpoint.

If only one optional argument is given, check whether it resolves to an existing filesystem path: if so, treat it as the EVTX path; otherwise treat it as the timerange. If two are given, the first is the timerange and the second is the EVTX path.

Example:

```
/investigate-endpoint WIN-CLIENT01 7d C:\logs\WIN-CLIENT01
```

## Steps

1. Confirm the hostname was supplied; stop and ask if not.

2. If an EVTX path was given, confirm it exists and contains at least one `.evtx` file before running any Hayabusa tool. If it doesn't, tell the user and continue with SIEM-only analysis rather than fabricating evidence.

3. Query SIEM data for the hostname (and timerange, if given), if a SIEM MCP tool or resource is configured in this environment. Analyse the results and extract:
   - suspicious processes
   - users
   - IP addresses
   - files
   - commands
   - authentication activity

   If no SIEM integration is available, say so explicitly in the output rather than silently skipping this step.

4. If an EVTX path was given, use the Hayabusa MCP tools:
   - `scan_evtx`, `hayabusa_log_metrics`, `hayabusa_computer_metrics` for a first-pass overview
   - `hayabusa_search`, `hayabusa_json_timeline`, `hayabusa_pivot_keywords_list`, `hayabusa_logon_summary` to dig into anything suspicious

   Look for the same categories as the SIEM step (processes, commands, users, authentication activity, persistence indicators) so the two sources are directly comparable.

5. Correlate SIEM and Hayabusa findings for the same hostname/timerange. The same process, user, or IP appearing in both sources strengthens confidence; a finding present in only one source should be flagged as unconfirmed by the other, not silently merged into one line.

6. Identify possible MITRE ATT&CK techniques from the correlated and standalone findings.

7. Use the detection MCP resources to check, for every identified technique:
   - `analyze_coverage`
   - `hayabusa://attack/techniques/{technique_id}`
   - `suggest_rule`

   Determine which techniques are covered, which aren't, and which Sigma rules are relevant.

8. Generate an Obsidian-compatible investigation note (see Output below) and save it under `investigations/` as `investigations/<hostname>_<YYYY-MM-DD>.md`, creating the directory if it doesn't exist. Report the saved path back to the user.

## Output

Start the file with an Obsidian frontmatter block:

```yaml
---
tags: [investigation, endpoint]
hostname: <hostname>
date: <YYYY-MM-DD>
timerange: <timerange, or "unspecified">
aliases: [<hostname>]
---
```

Followed by the report body:

# Endpoint Investigation: <hostname>

## Endpoint

## Timeline

## Findings

### SIEM

### Hayabusa

### Correlated

## ATT&CK Techniques

| Technique | Description | Source |
|---|---|---|
| | | |

Reference each technique as a wikilink or tag (e.g. `[[T1003.002]]` or `#attack/t1003.002`) so Obsidian's graph view and backlinks pick it up.

## Detection Coverage

| Technique | Status | Rule |
|---|---|---|
| | | |

## Recommendations

- Investigate uncovered techniques.
- Review existing detections.
- Improve detection coverage where gaps exist.
