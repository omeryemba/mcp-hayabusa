# Fixture provenance

Every `.evtx` file in this directory is a minimal, filtered excerpt of a
real sample from the public
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
corpus, which declares the **GPL-3.0** license. This project (`mcp-hayabusa`)
is MIT-licensed; vendoring these excerpts does not relicense this project's
own code, but the excerpted event data itself originates from that
GPL-3.0-declared corpus and is attributed here per file.

Each excerpt was produced with `wevtutil epl <source> <out> /lf:true
"/q:<XPath RecordID filter>" /ow:true`, then verified by actually running
the target rule against the resulting file with a real `hayabusa` binary
before being committed — every hit count below is a confirmed, reproduced
result, not a carried-over claim from a past investigation.

The hayabusa version these hit counts are verified against is the
`HAYABUSA_VERSION` pin in `.github/workflows/test.yml`'s
`validate-rule-execution` job (currently `3.10.0`), which re-runs every
rule against these fixtures on every CI run. Bump the two together: if
you change `HAYABUSA_VERSION`, re-run `validate-rule-execution.py`
locally against these fixtures first and update any hit counts below
that shift before committing the version bump.

`.evtx`'s chunk-based format has a fixed per-file overhead regardless of
how few events it holds — every file below is 68 KiB (the minimum this
format allows), even where it contains a single record.

## admin_share_access_smb.evtx

- Source: `Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx`, EventRecordIDs 566841, 566845, 566847 (Security/5140, `ShareName: \\*\ADMIN$`).
- Rule: `admin_share_access_smb.yml` — expect: fires, confirmed 3/3.

## admin_share_access_smb__negative.evtx

- Source: same file as above, EventRecordID 566831 (Security/5140, `ShareName: \\*\IPC$`).
- Rule: `admin_share_access_smb.yml` — expect: no_fire, confirmed 0/1.

## admin_share_write_access_smb.evtx

- Source: `Credential Access/remote_sam_registry_access_via_backup_operator_priv.evtx`, EventRecordIDs 2988537-2988542 (Security/5145, `ShareName: \\*\C$`, real combined `AccessMask` values `0x120196` and `0x2` — both prose scenarios documented in `admin_share_write_access_smb.testcases.md` are present in this one excerpt).
- Rule: `admin_share_write_access_smb.yml` — expect: fires, confirmed 6/6.

## admin_share_write_access_smb__negative.evtx

- Source: `Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx`, EventRecordID 566842 (Security/5145, `ShareName: \\*\ADMIN$`, `AccessMask: 0x1` — read-only).
- Rule: `admin_share_write_access_smb.yml` — expect: no_fire, confirmed 0/1.

## authentication_package_lsa_persistence__negative.evtx

- Source: `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx`, EventRecordID 3632 (Sysmon/13, `EventType: SetValue`, `TargetObject` ending `...\Control\Lsa\Notification Packages`).
- Rule: `authentication_package_lsa_persistence.yml` — expect: no_fire, confirmed 0/1.
- Note: this is the exact `Notification Packages` scenario documented in the rule's `.testcases.md` negative case — an earlier version of this fixture stood in a different real sample (`...\CurrentVersion\Run\360v`) because a corpus-wide search at the time turned up no `Notification Packages` match; a later, more thorough search (2026-07-30) found this one. No real sample of the rule's actual **positive** target (`...\Control\Lsa\Authentication Packages`) exists anywhere in the EVTX-ATTACK-SAMPLES corpus (confirmed via exact-phrase, broad-keyword, and regex searches covering all 278 files) — that case remains prose-only/unconfirmed, same as documented in the rule's own `status: test` history.

## remote_registry_service_started__negative.evtx

- Source: `Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx`, EventRecordID 65371 (System/7036, `Provider_Name: Service Control Manager`, `param1: Windows Error Reporting Service`, `param2: running`).
- Rule: `remote_registry_service_started.yml` — expect: no_fire, confirmed 0/1.
- Note: no real "Remote Registry" EID 7036 sample exists in this corpus — this rule's **positive** case remains prose-only/unconfirmed. This negative excerpt confirms real field names (`param1`/`param2`/`Provider_Name`) for this event family and that an unrelated service's `running` transition correctly does not fire.

## sensitive_privilege_use_backup_restore__negative.evtx

- Source: `Privilege Escalation/security_4624_4673_token_manip.evtx`, EventRecordID 18200 (Security/4673, `PrivilegeList: SeTcbPrivilege`).
- Rule: `sensitive_privilege_use_backup_restore.yml` — expect: no_fire, confirmed 0/1.
- Note: a corpus-wide search confirmed the only real EID 4673 samples in EVTX-ATTACK-SAMPLES carry `SeTcbPrivilege`, never `SeBackupPrivilege`/`SeRestorePrivilege` — this rule's **positive** case remains prose-only/unconfirmed, as already disclosed in the rule's own `status: experimental` history.
