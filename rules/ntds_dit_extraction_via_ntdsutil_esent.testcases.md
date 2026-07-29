# Test cases: ntds_dit_extraction_via_ntdsutil_esent

## Positive (must match)

Application-log ESENT Event ID 326, `ntds.dit` path in `Data[5]` — the
real field shape confirmed against `dc_applog_ntdsutil_dfir_325_326_327.evtx`
(EVTX-ATTACK-SAMPLES corpus) that the flat-`Data`-field builtin rule
(`win_esent_ntdsutil_abuse.yml`) cannot match:

```
Channel:       Application
Provider_Name: ESENT
EventID:       326
Data[1]:       NTDS
Data[2]:       3392
Data[4]:       1
Data[5]:       C:\$SNAP_201911270054_VOLUMEC$\Windows\NTDS\ntds.dit
Data[6]:       0
```

`application` matches (`Channel: Application`); `selection_eid` matches
(`Provider_Name: ESENT`, `EventID: 326`); `selection_path` matches (`Data[5]`
contains `ntds.dit`) → all three true → rule fires.

## Positive (must match)

Event ID 325, `ntds.dit` path written to a non-default, user-writable
location — the more suspicious of the two paths seen in the sample data:

```
Channel:       Application
Provider_Name: ESENT
EventID:       325
Data[1]:       NTDS
Data[2]:       3392
Data[4]:       2
Data[5]:       C:\Users\bob\Desktop\test\Folder\ntds\Active Directory\ntds.dit
Data[6]:       0
```

All three selections match → rule fires.

## Positive (must match)

Event ID 327 (the "completed" event of the same operation) — confirms the
rule fires across all four documented event IDs, not just one:

```
Channel:       Application
Provider_Name: ESENT
EventID:       327
Data[1]:       NTDS
Data[5]:       C:\$SNAP_201911270054_VOLUMEC$\Windows\NTDS\ntds.dit
```

`selection_eid` matches (`EventID: 327` is in the list) → rule fires.

## Negative (must not match)

Same ESENT/NTDS event family, but for an unrelated database file (not
`ntds.dit`) — e.g. a routine online defragmentation/consistency-check
event that also uses these event IDs:

```
Channel:       Application
Provider_Name: ESENT
EventID:       326
Data[1]:       NTDS
Data[5]:       C:\Windows\NTDS\edb.chk
```

`application` and `selection_eid` match, but no `Data[N]` contains
`ntds.dit` → `selection_path` does not match → rule does not match.

## Negative (must not match)

Correct provider and path, but an EventID outside the four this rule
tracks:

```
Channel:       Application
Provider_Name: ESENT
EventID:       102
Data[5]:       C:\Windows\NTDS\ntds.dit
```

`selection_eid` does not match (`102` not in the EventID list) → rule
does not match.

## Negative (must not match)

Same EventID/path, but a different Provider_Name — confirms the rule
doesn't accidentally match on EventID/Data alone:

```
Channel:       Application
Provider_Name: MsiInstaller
EventID:       326
Data[5]:       C:\Windows\NTDS\ntds.dit
```

`selection_eid` does not match (`Provider_Name` isn't `ESENT`) → rule
does not match.

## Known limitation (documented in `description`)

`Data[1]` through `Data[8]` are checked defensively because the `ntds.dit`
path's exact index is only empirically confirmed (index 5) for EventIDs
325/326/327, from the one available sample file. EventID 216 was not
independently sampled — if its parameter layout differs enough to push
the path outside indices 1-8, this rule would still miss it.
