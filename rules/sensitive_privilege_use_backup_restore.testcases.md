# Test cases: sensitive_privilege_use_backup_restore

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

## Known limitation (documented in `falsepositives`)

This event is only generated if "Audit: Audit the use of Backup and
Restore privilege" is separately enabled — Windows suppresses these two
privileges from Sensitive Privilege Use auditing by default even when
that subcategory is otherwise on. A deployment relying on this rule
without that policy set will see no coverage at all, silently.
