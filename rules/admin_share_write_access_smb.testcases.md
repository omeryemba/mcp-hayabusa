# Test cases: admin_share_write_access_smb

An earlier version of this rule matched an exact `AccessMask: '0x2'`,
copied from the builtin it's derived from. Confirmed against real
EVTX-ATTACK-SAMPLES EID 5145 events (RemCom/renamed-PsExec/Backup-
Operator-privilege corpus samples) that this misses nearly every real
write: Windows almost always logs a combined mask (`0x120196`, `0x3`,
`0x83`, `0x12019f` were all observed) with the `FILE_WRITE_DATA` bit
(bit 1) set alongside other granted rights, not a bare `0x2`. Fixed by
replacing the exact match with `AccessMask|re: '[2367abABEF]$'`, which
tests only the low nibble's bit 1 — matching any mask ending in a hex
digit that has that bit set (`2,3,6,7,A,B,E,F`), independent of higher
bits. Re-verified 2026-07-30: this rule went from 0 hits to 14 hits
against the real corpus (10 with combined masks like `0x120196`, 4 with
the bare `0x2` this rule already caught), correctly still excluding
every read-only (`0x1`-family) event.

## Positive (must match)

Security Event ID 5145, a non-system account writing a file to `ADMIN$`
with a real-world combined access mask (`0x120196` — READ_CONTROL,
SYNCHRONIZE, WRITE_DATA, APPEND_DATA, WRITE_EA, READ_ATTRIBUTES,
WRITE_ATTRIBUTES) — the exact pattern the earlier exact-`0x2` match
missed on every real sample tested:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\ADMIN$
AccessMask:       0x120196
SubjectUserName:  jdoe
IpAddress:        10.0.0.5
```

```yaml
fixture: admin_share_write_access_smb.evtx
expect: fires
min_hits: 6
```

`security`/`selection` match (`EventID: 5145`, `AccessMask` ends in `6`,
which is in `[2367abABEF]`); `selection_admin_share` matches (`\ADMIN$`);
neither filter applies → rule fires.

## Positive (must match)

Bare `AccessMask: 0x2` — the literal value the original rule checked
for, confirmed still caught by the fixed regex (also seen for real in
this corpus, alongside `0x120196`, on the same host/share):

```
Channel:          Security
EventID:          5145
ShareName:        \\*\C$
AccessMask:       0x2
SubjectUserName:  jdoe
IpAddress:        10.0.0.5
```

All selections match (`AccessMask` ends in `2`) → rule fires.

## Negative (must not match)

Read access (`AccessMask: 0x1`), not a write — reconnaissance, not
payload staging:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\ADMIN$
AccessMask:       0x1
SubjectUserName:  jdoe
```

```yaml
fixture: admin_share_write_access_smb__negative.evtx
expect: no_fire
```

`AccessMask` ends in `1`, not in `[2367abABEF]` → `selection` does not
match → rule does not match.

## Negative (must not match)

A real-world combined mask that does *not* include the write bit
(`0x100081` — SYNCHRONIZE, READ_ATTRIBUTES, READ_DATA — observed for
real in this corpus alongside the genuine write events above) —
confirms the regex fix doesn't over-match on "any non-trivial mask":

```
Channel:          Security
EventID:          5145
ShareName:        \\*\ADMIN$
AccessMask:       0x100081
SubjectUserName:  jdoe
```

`AccessMask` ends in `1`, not in `[2367abABEF]` → `selection` does not
match → rule does not match.

## Negative (must not match)

Write to `IPC$` — named-pipe traffic, not a real file-share write,
deliberately excluded by the admin-share regex:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\IPC$
AccessMask:       0x2
SubjectUserName:  jdoe
```

`selection_admin_share` does not match → rule does not match.

## Negative (must not match)

Computer account writing to `ADMIN$` from localhost (`::1`) — routine
local system/service activity, filtered out by both filters:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\ADMIN$
AccessMask:       0x2
SubjectUserName:  WORKSTATION1$
IpAddress:        ::1
```

`selection` and `selection_admin_share` match, but
`filter_main_subjectusername` also matches (`WORKSTATION1$` ends `$`) →
excluded → rule does not match.

## Known limitation (documented in `description`)

Requires the advanced audit policy "Object Access > Audit Detailed File
Share" to be configured for Success/Failure — not on by default.
