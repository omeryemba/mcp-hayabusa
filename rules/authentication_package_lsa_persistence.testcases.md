# Test cases: authentication_package_lsa_persistence

An earlier version of this rule had no `Channel` selector at all, which
caused hayabusa's channel filter to exclude every input file and disable
the rule entirely (confirmed via `-v` output: `Evtx files loaded after
channel filter: 0`, `Detection rules enabled after channel filter: 0`) —
a guaranteed zero-detection rule regardless of real activity. Fixed by
adding a `registry_set: {Channel: Microsoft-Windows-Sysmon/Operational}`
selection block. Re-verified 2026-07-29 with a rule clone matching a real
Sysmon EventID 13 SetValue sample (`\CurrentVersion\Run\360v` from
`DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, EVTX-ATTACK-SAMPLES
corpus): without the `Channel` block, 0/1; with it, 1/1. `TargetObject`
and `EventType` were confirmed as correct, real field names for this
event once the channel gate was in place — they were never the problem.
`logsource.category` was also corrected from `registry_event` to
`registry_set` on 2026-07-30 to match this project's own installed
builtin convention for this exact detection shape (Sysmon EventID 13
SetValue) — cosmetic only, doesn't change matching behavior. Status
promoted to `test` the same day given the confirmed real-sample firing
above.

## Positive (must match)

Sysmon Event ID 13 (RegistryEvent — Value Set), an attacker registering a
malicious authentication package DLL for persistent, SYSTEM-context
execution inside lsass.exe on next boot:

```
Channel:      Microsoft-Windows-Sysmon/Operational
EventID:      13
EventType:    SetValue
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
Details:      msv1_0 C:\Windows\System32\evilauthpkg.dll
Image:        C:\Windows\System32\reg.exe
```

`registry_set` matches (`Channel: Microsoft-Windows-Sysmon/Operational`),
`selection_target` matches `TargetObject` (ends with `\Control\Lsa\Authentication
Packages`), `selection_type` matches `EventType: SetValue` → all three true
→ rule fires.

## Negative (must not match)

Sysmon Event ID 13 on an unrelated LSA registry value (Notification Packages),
same event type, different target:

```
Channel:      Microsoft-Windows-Sysmon/Operational
EventID:      13
EventType:    SetValue
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
Details:      scecli
Image:        C:\Windows\System32\lsass.exe
```

```yaml
fixture: authentication_package_lsa_persistence__negative.evtx
expect: no_fire
```

Execution-test fixture note: this negative case is backed by a real
`Notification Packages` sample (`AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx`,
EventRecordID 3632, EVTX-ATTACK-SAMPLES) — the exact scenario described
above. An earlier version of this fixture used a different real sample
(`...\CurrentVersion\Run\360v`) as a stand-in, from a time when no
`Notification Packages` match had yet been found in the corpus; a later,
more thorough search turned one up. See `tests/fixtures/evtx/PROVENANCE.md`.

`selection_target` does not match (`TargetObject` doesn't end with `\Control\Lsa\
Authentication Packages`) → rule does not fire.

## Negative (must not match)

Sysmon Event ID 12 (RegistryEvent — Key/Value Create/Delete) against the correct
key, but the wrong event type — this rule intentionally scopes to `SetValue` only:

```
Channel:      Microsoft-Windows-Sysmon/Operational
EventID:      12
EventType:    CreateKey
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
Image:        C:\Windows\System32\services.exe
```

`selection_target` matches, but `selection_type` does not (`EventType` is
`CreateKey`, not `SetValue`) → condition requires both → rule does not fire.

## Negative (must not match)

Otherwise-matching event content, but from a channel other than the one this
rule is scoped to — confirms the `registry_set` channel gate actually
constrains matching rather than being decorative:

```
Channel:      Security
EventID:      13
EventType:    SetValue
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
```

`registry_set` does not match (`Channel` isn't
`Microsoft-Windows-Sysmon/Operational`) → rule does not fire.

## Known limitation (documented in `falsepositives`)

The rule fires on any `SetValue` event against this registry value regardless of
which DLL is actually named in the new value, since Sysmon's `registry_set`
category does not reliably expose full value contents (`Details`) for every
provider/event combination. A true positive (attacker-added DLL) and a benign
one (legitimate SSO/smart-card software reconfiguring LSA, or an OS update
resetting the default) are indistinguishable at the event level alone — triage
must inspect the actual DLL named in the new value, confirm it's signed, and
check it against known-vendor install paths before escalating.
