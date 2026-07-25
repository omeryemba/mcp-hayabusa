# Test cases: lsass_memory_access

## Positive (must match)

Sysmon Event ID 10 (ProcessAccess), an unlisted process opening LSASS with a
credential-dumping-capable access mask:

```
SourceImage:  C:\Users\Public\procdump64.exe
TargetImage:  C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff
CallTrace:    C:\Windows\SYSTEM32\ntdll.dll+9d824|C:\Windows\System32\KERNELBASE.dll+2c3ee|...
```

`selection_target` matches `TargetImage`, `selection_access` matches `GrantedAccess`,
and `SourceImage` (`procdump64.exe`) is not in `filter_known_benign_sources` →
condition is true → rule fires.

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

## Known limitation (documented in `falsepositives`)

`filter_known_benign_sources` is a static, environment-specific allow-list. Any
EDR/AV/backup/monitoring agent not already listed there will trigger a false
positive until its SourceImage path is added — this is expected and should be
tuned per-deployment rather than treated as a rule defect.
