---
name: detection-engineering
description: Use when writing or creating Sigma rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files. Enforces this project's detection rule standards (ATT&CK mapping, severity justification, false positive documentation, test cases, naming conventions).
---

# Detection Engineering Standards

Enforce these standards on every Sigma/detection rule this project writes, reviews, or discusses. Apply them whether authoring a new rule, editing an existing one, or reviewing someone else's — flag any rule that doesn't meet them rather than silently passing it.

## Standards checklist

1. **ATT&CK technique mapping required.** Every rule must include at least one `attack.tXXXX` tag (e.g. `attack.t1059.001`), lowercase, in the rule's `tags:` field. A rule with no ATT&CK tag is incomplete — do not approve or ship it without one, and don't invent a technique ID that doesn't fit; ask or leave it flagged if the right mapping isn't obvious.

2. **Severity must be justified.** The `level:` field must be one of `low`, `medium`, `high`, `critical` — no other values. Every rule must also carry a short justification for why that level was chosen (e.g. in the `description:` field or an inline comment), not just the bare level. "high because X" is required, "high" alone is not sufficient.

3. **False positive conditions must be documented.** Every rule must have a `falsepositives:` field listing realistic conditions that would cause benign activity to match (e.g. specific admin tools, scheduled tasks, software installers). An empty list, `Unknown`, or omitting the field is not acceptable — if you genuinely can't identify any, that itself is a red flag worth raising rather than silently accepting.

4. **At least one test case is required.** Every rule must be accompanied by at least one test case demonstrating it fires on the intended malicious/suspicious behavior (a sample log record, an `.evtx` fixture, or an equivalent documented scenario). A rule with no test case is not done.

5. **Naming convention.** Rule names (the `title:`-derived identifier / filename, not necessarily the human-readable `title:` string itself) must be lowercase with underscores — e.g. `suspicious_powershell_encoded_command`, not `SuspiciousPowerShellEncodedCommand` or `suspicious-powershell-encoded-command`.

## How to apply

- **When writing a new rule:** produce all five elements up front — don't leave ATT&CK mapping, false positives, or a test case as a "TODO" for later.
- **When reviewing a rule:** check it against this list explicitly and call out exactly which item(s) are missing or insufficient, not just "looks fine."
- **When discussing detection coverage:** frame gaps in terms of ATT&CK technique coverage (this project's `analyze_coverage`/`suggest_rule` tools already report coverage this way — align terminology with that).
- **When working with any YAML detection file:** treat these five checks as a gate before considering the file complete, regardless of which specific tool or task triggered the edit.

## References

When writing rules, consult:
- references/example-rules/ - Well-formatted examples to follow
- references/severity-guide.md - Severity level guidance
- references/false-positive-patterns.md - Common false positive documentation patterns
