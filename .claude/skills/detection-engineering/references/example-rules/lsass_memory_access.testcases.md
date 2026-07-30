# Test cases: lsass_memory_access

An earlier version of this rule had no `Channel` selector at all, which caused
hayabusa's channel filter to exclude every input file and disable the rule
entirely (confirmed via `-v` output: `Evtx files loaded after channel filter:
0`) — a guaranteed zero-detection rule regardless of real activity, even
though every field it references (`TargetImage`, `SourceImage`,
`GrantedAccess`) was already a correct, real Sigma field name. Fixed by
adding a `process_access: {Channel: Microsoft-Windows-Sysmon/Operational,
EventID: 10}` selection block. Re-verified 2026-07-30 against a real sample
(`PanacheSysmon_vs_AtomicRedTeam01.evtx`, EVTX-ATTACK-SAMPLES corpus,
PowerShell opening lsass.exe with `GrantedAccess: 0x1010`): without the
`Channel` block, 0/1; with it, 1/1. This is the exact defect this rule's own
falsepositives/description otherwise correctly document — a reminder that
`logsource.category` alone (`process_access` here) does not make hayabusa
infer a channel; every rule needs its own explicit `Channel`/`EventID` gate
ANDed into `condition:`.

## Positive (must match) — confirmed firing

Sysmon Event ID 10 (ProcessAccess), an unlisted process opening LSASS with a
credential-dumping-capable access mask:

```
Channel:      Microsoft-Windows-Sysmon/Operational
EventID:      10
SourceImage:  C:\Users\Public\procdump64.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
CallTrace:    C:\Windows\SYSTEM32\ntdll.dll+9d824|C:\Windows\System32\KERNELBASE.dll+2c3ee|...
```

`process_access` matches (`Channel: Microsoft-Windows-Sysmon/Operational`,
`EventID: 10`); `selection_target` matches `TargetImage`; `selection_access`
matches `GrantedAccess`; `SourceImage` (`procdump64.exe`) is not in
`filter_known_benign_sources` → condition is true → rule fires.

## Negative (must not match)

Same access mask, but from a known-benign, filtered source image (Microsoft Defender):

```
SourceImage:  C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5\MsMpEng.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
```

`selection_target` and `selection_access` both match, but `SourceImage` ends with
`\MsMpEng.exe`, so `filter_known_benign_sources` matches too → `not filter_known_benign_sources`
is false → rule does not fire.

## Negative (must not match)

Access to lsass.exe with a low-privilege, non-dumping access mask (e.g. `0x1000`,
query limited information only):

```
SourceImage:  C:\Windows\System32\Taskmgr.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1000
```

`selection_access` does not match any listed GrantedAccess value → rule does not fire.

## Negative (must not match)

Otherwise-matching event content, but from a channel other than the one this
rule is scoped to — confirms the `process_access` channel gate actually
constrains matching rather than being decorative:

```
Channel:      Security
EventID:      10
SourceImage:  C:\Users\Public\procdump64.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
```

`process_access` does not match (`Channel` isn't
`Microsoft-Windows-Sysmon/Operational`) → rule does not fire.

## Known limitation (documented in `falsepositives`)

`filter_known_benign_sources` is a static, environment-specific allow-list. Any
EDR/AV/backup/monitoring agent not already listed there will trigger a false
positive until its SourceImage path is added — this is expected and should be
tuned per-deployment rather than treated as a rule defect.
