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

## Validation

After creating or modifying a rule, validate it against these standards with the skill's own script rather than eyeballing compliance:

```
python .claude/skills/detection-engineering/scripts/validate-rule.py path/to/rule.yml
```

- **Input:** a single positional argument — the path to the Sigma rule YAML file to check.
- **Checks performed:** the same four machine-checkable standards from the checklist above — an `attack.tXXXX`/`attack.tXXXX.XXX` technique tag is present (standard 1); `level:` is one of `low`, `medium`, `high`, `critical` (standard 2); `falsepositives:` exists and contains at least one real, non-placeholder entry, not `Unknown` or empty (standard 3); a sibling `<rule-stem>.testcases.md` file exists next to the rule and is non-empty (standard 4). Naming convention (standard 5) isn't checked by the script — verify that one by eye.
- **Output:** a JSON report on stdout — `valid`, a per-check breakdown, and an `issues` list explaining anything that failed — plus an exit code (`0` valid, `1` one or more checks failed, `2` usage/parse error such as a missing file or malformed YAML).

Treat a non-zero exit as the rule not being done yet — fix what `issues` calls out and re-run rather than shipping a rule the script hasn't passed.

`validate-rule.py` only checks that standard 4's `.testcases.md` file *exists* and is non-empty — it never runs the rule against real data, so a rule can pass every check above and still be structurally broken (this project has shipped exactly that kind of bug before: a fake field reference, a missing `Channel` gate, an exact-match false negative — see `investigations/SAMPLE-EVTX-01.md`). Close that gap with the execution-based runner:

```
python .claude/skills/detection-engineering/scripts/validate-rule-execution.py rules/
```

This actually runs each rule against a real `.evtx` fixture via a real `hayabusa` binary and checks it fires/doesn't fire as documented in machine-readable ` ```yaml ` blocks embedded in the rule's `.testcases.md`, e.g.:

```yaml
fixture: my_rule.evtx
expect: fires        # or: no_fire
min_hits: 1           # optional, default 1, ignored when expect: no_fire
```

Add one such block per `## Positive`/`## Negative` case you can back with a real fixture — additive alongside the existing prose, which stays as human-readable documentation. Unlike `validate-rule.py`, this script needs the `mcp_hayabusa` package installed and a real `hayabusa` binary on `PATH`/`HAYABUSA_BIN`, and **it is not currently wired into CI** — nothing blocks a merge on it failing yet, so run it manually and don't treat a rule as done until it passes. Fixtures resolve from `HAYABUSA_SAMPLE_EVTX_DIR` if set, else the small real excerpts vendored under `tests/fixtures/evtx/` (sourced/attributed in `tests/fixtures/evtx/PROVENANCE.md`). If no real sample exists for a scenario, leave it prose-only rather than inventing a fixture or a fake result — an honestly-undocumented case is better than a fabricated pass.

## References

When writing rules, consult:
- references/example-rules/ - Well-formatted examples to follow
- references/severity-guide.md - Severity level guidance
- references/false-positive-patterns.md - Common false positive documentation patterns
