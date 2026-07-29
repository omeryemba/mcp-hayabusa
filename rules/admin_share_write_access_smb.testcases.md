# Test cases: admin_share_write_access_smb

## Positive (must match)

Security Event ID 5145, a non-system account writing a file to `ADMIN$`
— the gap the `C$`-only builtin rule
(`win_security_smb_file_creation_admin_shares.yml`) misses entirely:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\ADMIN$
AccessMask:       0x2
SubjectUserName:  jdoe
IpAddress:        10.0.0.5
```

`security`/`selection` match (`EventID: 5145`, `AccessMask: 0x2`);
`selection_admin_share` matches (`\ADMIN$`); neither filter applies →
rule fires.

## Positive (must match)

Same write, `C$` — the case the builtin rule already covers, kept here
to confirm this rule doesn't regress it:

```
Channel:          Security
EventID:          5145
ShareName:        \\*\C$
AccessMask:       0x2
SubjectUserName:  jdoe
IpAddress:        10.0.0.5
```

All selections match → rule fires.

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

`selection` requires `AccessMask: 0x2` → does not match → rule does not
match.

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
