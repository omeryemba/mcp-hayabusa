# Test cases: sensitive_privilege_use_backup_restore

An earlier version of this rule had no `Channel` selector at all, which
caused hayabusa's channel filter to exclude every input file and disable
the rule entirely (confirmed via `-v` output: `Evtx files loaded after
channel filter: 0`, even scanned against a 278-file corpus) — a
guaranteed zero-detection rule regardless of real activity. Fixed by
adding a `security: {Channel: Security}` selection block, matching every
other Security-log rule in this project's set. No real EventID 4673
sample with SeBackupPrivilege/SeRestorePrivilege exists in the
EVTX-ATTACK-SAMPLES corpus to test end-to-end (only EventID 4672/4703
privilege-grant samples were found, a different, much noisier event this
rule intentionally excludes), so the positive cases below remain
scenario-based rather than confirmed against a real sample.

## Positive (must match)

Security Event ID 4673, a process invoking SeBackupPrivilege — the
mechanism Impacket's `secretsdump.py`/`reg.py` registry method uses to
read the SAM hive without local admin rights:

```
EventID:        4673
Channel:        Security
SubjectUserName: bkupsvc
PrivilegeList:  SeBackupPrivilege
Service:        -
ProcessName:    C:\Windows\System32\svchost.exe
```

`selection` matches (`EventID: 4673`, `PrivilegeList` contains
`SeBackupPrivilege`) → rule fires.

## Positive (must match)

Same event, SeRestorePrivilege instead:

```
EventID:        4673
Channel:        Security
SubjectUserName: attacker
PrivilegeList:  SeRestorePrivilege
```

`selection` matches (`PrivilegeList` contains `SeRestorePrivilege`) →
rule fires.

## Negative (must not match)

Event ID 4673 for an unrelated sensitive privilege (SeDebugPrivilege,
e.g. a debugger or EDR agent attaching to a process):

```
EventID:        4673
Channel:        Security
SubjectUserName: edragent
PrivilegeList:  SeDebugPrivilege
```

`selection` does not match (`PrivilegeList` doesn't contain
`SeBackupPrivilege`/`SeRestorePrivilege`) → rule does not match.

## Negative (must not match)

Event ID 4672 (privileges assigned at logon, not a privileged service
call) listing the same privileges — this rule intentionally scopes to
4673 only, since 4672 fires for every admin logon and would be far too
noisy/non-specific for this signal:

```
EventID:        4672
Channel:        Security
SubjectUserName: bkupsvc
PrivilegeList:  SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege
```

`selection` does not match (`EventID` is `4672`, not `4673`) → rule does
not match.

## Negative (must not match)

Otherwise-matching event content, but from a channel other than the one
this rule is scoped to — confirms the `security` channel gate actually
constrains matching rather than being decorative:

```
EventID:        4673
Channel:        Application
PrivilegeList:  SeBackupPrivilege
```

`security` does not match (`Channel` isn't `Security`) → rule does not
match.

## Known limitation (documented in `falsepositives`)

This event is only generated if "Audit: Audit the use of Backup and
Restore privilege" is separately enabled — Windows suppresses these two
privileges from Sensitive Privilege Use auditing by default even when
that subcategory is otherwise on. A deployment relying on this rule
without that policy set will see no coverage at all, silently.
