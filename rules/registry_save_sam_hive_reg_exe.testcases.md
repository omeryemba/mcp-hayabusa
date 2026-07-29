# Test cases: registry_save_sam_hive_reg_exe

## Positive (must match)

Process creation, `reg.exe` saving the SAM hive to a local file — the
classic local precursor to offline hash extraction:

```
Image:       C:\Windows\System32\reg.exe
CommandLine: reg.exe save HKLM\SAM C:\Windows\Temp\sam.hive
```

`selection_reg` matches (`Image` ends with `\reg.exe`), `selection_verb`
matches (` save `), `selection_hive` matches (`hklm\sam`, case-insensitive)
→ all three true → rule fires.

## Positive (must match)

`reg.exe` exporting the SYSTEM hive (needed alongside SAM to derive the
boot key for offline decryption):

```
Image:       C:\Windows\System32\reg.exe
CommandLine: reg export HKLM\SYSTEM C:\Users\Public\sys.reg
```

All three selections match → rule fires.

## Negative (must not match)

`reg.exe` querying (not saving/exporting) the SAM hive — read-only
enumeration, not a hive export:

```
Image:       C:\Windows\System32\reg.exe
CommandLine: reg query HKLM\SAM
```

`selection_reg` and `selection_hive` match, but `selection_verb` does
not (no ` save `/` export ` substring) → condition requires all three →
rule does not match.

## Negative (must not match)

`reg.exe` exporting an unrelated, non-credential registry key:

```
Image:       C:\Windows\System32\reg.exe
CommandLine: reg export HKCU\Software\MyApp C:\Users\Public\myapp.reg
```

`selection_reg` and `selection_verb` match, but `selection_hive` does
not (no SAM/SECURITY/SYSTEM substring) → rule does not match.

## Known limitation (documented in `description`)

This rule only covers the local `reg.exe` process-creation vector. A
Backup Operator (or other SeBackupPrivilege holder) dumping these same
hives remotely over the winreg RPC interface never spawns `reg.exe` on
the target — see `sensitive_privilege_use_backup_restore.yml` and
`remote_registry_service_started.yml` for that vector instead.
