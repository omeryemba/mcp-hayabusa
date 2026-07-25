# Test cases: authentication_package_lsa_persistence

## Positive (must match)

Sysmon Event ID 13 (RegistryEvent — Value Set), an attacker registering a
malicious authentication package DLL for persistent, SYSTEM-context
execution inside lsass.exe on next boot:

```
EventID:      13
EventType:    SetValue
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
Details:      msv1_0 C:\Windows\System32\evilauthpkg.dll
Image:        C:\Windows\System32\reg.exe
```

`selection_target` matches `TargetObject` (ends with `\Control\Lsa\Authentication
Packages`), `selection_type` matches `EventType: SetValue` → both selections true
→ rule fires.

## Negative (must not match)

Sysmon Event ID 13 on an unrelated LSA registry value (Notification Packages),
same event type, different target:

```
EventID:      13
EventType:    SetValue
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
Details:      scecli
Image:        C:\Windows\System32\lsass.exe
```

`selection_target` does not match (`TargetObject` doesn't end with `\Control\Lsa\
Authentication Packages`) → rule does not fire.

## Negative (must not match)

Sysmon Event ID 12 (RegistryEvent — Key/Value Create/Delete) against the correct
key, but the wrong event type — this rule intentionally scopes to `SetValue` only:

```
EventID:      12
EventType:    CreateKey
TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
Image:        C:\Windows\System32\services.exe
```

`selection_target` matches, but `selection_type` does not (`EventType` is
`CreateKey`, not `SetValue`) → condition requires both → rule does not fire.

## Known limitation (documented in `falsepositives`)

The rule fires on any `SetValue` event against this registry value regardless of
which DLL is actually named in the new value, since Sysmon's `registry_event`
category does not reliably expose full value contents (`Details`) for every
provider/event combination. A true positive (attacker-added DLL) and a benign
one (legitimate SSO/smart-card software reconfiguring LSA, or an OS update
resetting the default) are indistinguishable at the event level alone — triage
must inspect the actual DLL named in the new value, confirm it's signed, and
check it against known-vendor install paths before escalating.
