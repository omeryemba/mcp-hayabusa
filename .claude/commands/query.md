---
name: query
description: Query SIEM and check detection coverage
---

# Workflow

You are performing a defensive security investigation.

## Steps

1. Execute the SIEM query for the investigation target.

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
