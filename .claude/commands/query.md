---
name: query
description: Query SIEM and check detection coverage
---

# Workflow

You are performing a defensive security investigation.

## Input

Arguments: $ARGUMENTS

Parse as:

1. **query_file** (required) — path to a file containing the SIEM query to run. If missing, stop and ask the user for a query file.
2. **timerange** (optional) — defaults to `-24h` if not given.

Example:

```
/query queries/suspicious_logons.txt -24h
```

## Steps

1. Confirm `query_file` was supplied and exists; stop and ask if not. Read the query from it, then execute that query for the given `timerange` (default `-24h`) against SIEM data, if a SIEM MCP tool or resource is configured in this environment. If no SIEM integration is available, say so explicitly rather than silently skipping this step.

2. Analyse the results and extract:
   - suspicious processes
   - users
   - IP addresses
   - files
   - commands
   - authentication activity

3. Identify possible MITRE ATT&CK techniques from the findings.

4. Use the detection MCP resources to check:
   - whether detection rules exist
   - which Sigma rules provide coverage
   - whether coverage gaps exist

5. Generate an investigation note.

## Output

# Investigation Summary

## Findings

## ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| | |

## Detection Coverage

| Technique | Status | Rule |
|-----------|--------|------|
| | | |

## Recommendations

- Investigate uncovered techniques.
- Review existing detections.
- Improve detection coverage where gaps exist.
