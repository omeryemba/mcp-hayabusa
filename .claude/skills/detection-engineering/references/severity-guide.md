# Severity Guide

Sigma's `level:` field must be one of `low`, `medium`, `high`, `critical` — no other
values (not `informational`, not a number, not a custom string). Every rule must also
carry a short justification for *why* that level was chosen (in `description:` or an
inline comment) — "high because X" is required, "high" alone is not sufficient.

Severity is a function of two things: how bad the underlying behavior is **if the
match is a true positive**, and how confident the detection logic itself is (i.e.
how likely a match is to actually be that behavior, vs. something benign that
happens to look similar). A very specific, low-noise detection of a moderately bad
behavior can outrank a noisy, ambiguous detection of a worse behavior — severity is
about the alert, not just the underlying ATT&CK technique's theoretical maximum impact.

## `low`

Use when a match is informational or only weakly suspicious on its own — useful for
correlation/hunting, but not something that should interrupt anyone by itself.

Typical characteristics:
- Reconnaissance or enumeration activity that's also common in normal admin/IT work
  (e.g. `whoami`, `net user`, directory listing of shares).
- Policy/hygiene violations rather than attack behavior (e.g. a service running as
  a disallowed account, a deprecated protocol version negotiated).
- Precursor activity several steps removed from actual impact, where the vast
  majority of matches in practice are benign.

Example justification: *"low because this only flags PowerShell `-EncodedCommand`
usage, which is routine in many legitimate admin scripts and deployment tools —
useful as a pivot/context signal alongside other alerts, not as a standalone alert."*

## `medium`

Use when a match indicates activity that is genuinely suspicious and worth an
analyst's attention, but where legitimate use is common enough (or the technique
alone is not sufficient for impact) that it shouldn't page anyone at 3am.

Typical characteristics:
- A dual-use tool or technique invoked in a slightly unusual way (e.g. `certutil`
  downloading a file, `rundll32` with an uncommon export).
- Early-stage attack behavior (initial access, weak persistence) where confirmation
  requires more context than the single event provides.
- Rules with a known, non-trivial false-positive rate even after reasonable tuning.

Example justification: *"medium because scheduled task creation with a suspicious
binary path is a common persistence technique, but this also matches legitimate
software installers that register update-checker tasks — needs analyst triage,
not automatic escalation."*

## `high`

Use when a match is a strong, largely unambiguous indicator of malicious activity,
and a true positive would have serious consequences (credential theft, code
execution, defense evasion, confirmed lateral movement) — but full compromise or
irreversible damage isn't yet certain, or the detection still has a plausible
(if narrow) benign explanation that a human should rule out first.

Typical characteristics:
- Credential access techniques with real-world impact (e.g. LSASS memory access,
  SAM/SECURITY hive access) — see `references/example-rules/lsass_memory_access.yml`
  for a worked example.
- Known offensive tool signatures (Cobalt Strike default indicators, Mimikatz
  command-line patterns) that are rare but not impossible in authorized red-team/
  pentest activity.
- Successful exploitation indicators for a specific, serious vulnerability.

Example justification: *"high because a successful high-privilege open handle to
LSASS is very often the direct precursor to credential theft, which commonly
enables lateral movement and privilege escalation; not critical because legitimate,
unlisted EDR/diagnostic tooling can still trigger this GrantedAccess pattern, so a
human should confirm SourceImage legitimacy before treating it as confirmed
compromise."*

## `critical`

Reserve for matches where, if true, there is no reasonable benign explanation and
the activity indicates *confirmed or near-certain* severe compromise or imminent
major impact — the kind of alert that justifies waking someone up immediately.

Typical characteristics:
- Ransomware-associated behavior with high specificity (mass file encryption
  patterns, shadow copy deletion combined with known ransom-note filenames).
- Direct evidence of a backdoor/webshell actually executing (not just being
  written to disk).
- Domain Admin / Enterprise Admin group membership changes performed outside
  documented change windows, combined with other compromise indicators.
- Destructive actions in progress (mass deletion, disk wiping commands).

Example justification: *"critical because shadow copy deletion via `vssadmin
delete shadows /all /quiet` immediately followed by mass file renames to a
ransomware-associated extension has no legitimate operational explanation and
indicates ransomware detonation is already underway."*

## Choosing between adjacent levels

When torn between two levels, ask:

1. **Could a normal admin/user/software update produce this exact match, doing
   nothing wrong?** If yes and it's plausible in most environments → drop one
   level from where the raw technique severity would suggest.
2. **Does firing require multiple independent suspicious conditions (an "and"
   of several selections/filters), or just one weak signal?** More conditions,
   tighter logic → can usually justify going up a level versus a single broad
   selection for the same technique.
3. **What's the realistic blast radius if this is a true positive and no one
   responds for an hour?** Data theft/lateral movement potential → `high`.
   Active destruction/irreversible impact → `critical`.

When still unsure, prefer the lower of the two candidate levels and say so
explicitly in the justification (e.g. "medium rather than high because...") —
an under-severe rule that's well-documented is easier to correct later than an
over-severe one that trains analysts to ignore its false positives.
