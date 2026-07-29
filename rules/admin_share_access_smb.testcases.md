# Test cases: admin_share_access_smb

## Positive (must match)

Security Event ID 5140, access to `ADMIN$` — the real field format
(`\\*\ADMIN$`) that the exact-match builtin rule
(`win_security_admin_share_access.yml`, `ShareName: Admin$`) can never
match:

```
Channel:          Security
EventID:          5140
ShareName:        \\*\ADMIN$
SubjectUserName:  jdoe
```

`security` and `selection` match on `EventID: 5140`; `selection_admin_share`
matches (`ShareName` ends `\ADMIN$`); `filter_main_computer_account` does
not apply (`jdoe` doesn't end in `$`) → rule fires.

## Positive (must match)

Drive-letter admin share (`C$`), the vector the builtin rule never
covered even in principle:

```
Channel:          Security
EventID:          5140
ShareName:        \\*\C$
SubjectUserName:  jdoe
```

`selection_admin_share` matches (`\C$` fits `[A-Za-z]\$` at end of
string) → rule fires.

## Negative (must not match)

Access to `IPC$` — used constantly for ordinary RPC/named-pipe traffic,
deliberately excluded (matches neither `ADMIN$` nor a single
drive-letter share):

```
Channel:          Security
EventID:          5140
ShareName:        \\*\IPC$
SubjectUserName:  jdoe
```

`selection_admin_share` does not match → rule does not match.

## Negative (must not match)

Access to an ordinary named share, not an administrative one:

```
Channel:          Security
EventID:          5140
ShareName:        \\*\Shared
SubjectUserName:  jdoe
```

`selection_admin_share` does not match → rule does not match.

## Negative (must not match)

Computer/service account (ends in `$`) accessing `ADMIN$` — routine
machine-account activity (e.g. Group Policy), filtered out:

```
Channel:          Security
EventID:          5140
ShareName:        \\*\ADMIN$
SubjectUserName:  WORKSTATION1$
```

`selection` and `selection_admin_share` match, but
`filter_main_computer_account` also matches (`SubjectUserName` ends `$`)
→ condition excludes it → rule does not match.

## Known limitation (documented in `description`)

Requires the advanced audit policy "Object Access > Audit File Share"
to be configured for Success/Failure — not on by default, same
prerequisite as the builtin rule this replaces.
