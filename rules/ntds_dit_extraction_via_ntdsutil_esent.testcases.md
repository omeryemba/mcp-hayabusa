# Test cases: ntds_dit_extraction_via_ntdsutil_esent

Executed against the real sample `dc_applog_ntdsutil_dfir_325_326_327.evtx`
(EVTX-ATTACK-SAMPLES corpus) via `hayabusa_csv_timeline` with
`rules_dir` pointed at this project's `rules/` directory, 2026-07-29.
An earlier version of this rule matched `Data[1]|contains` through
`Data[8]|contains` on the (incorrect) assumption that those are real,
independently-addressable Sigma field names; that version fired 0/4
times against this same file. The current version matches the flat
`Data|contains: ntds.dit` field instead (same selector the builtin
`win_esent_ntdsutil_abuse.yml` uses) and was confirmed to fire 4/4 times.

## Positive (must match) — confirmed firing

All 4 real events in the sample file match and produce a detection:

```
Channel:       Application
Provider_Name: ESENT
EventID:       326, RecordID 1969, Data: ... C:\$SNAP_201911270054_VOLUMEC$\Windows\NTDS\ntds.dit ...
EventID:       325, RecordID 1970, Data: ... C:\Users\bob\Desktop\test\Folder\ntds\Active Directory\ntds.dit ...
EventID:       327, RecordID 1971, Data: ... C:\Users\bob\Desktop\test\Folder\ntds\Active Directory\ntds.dit ...
EventID:       327, RecordID 1972, Data: ... C:\$SNAP_201911270054_VOLUMEC$\Windows\NTDS\ntds.dit ...
```

`application` matches (`Channel: Application`); `selection_eid` matches
(`Provider_Name: ESENT`, `EventID` in `216/325/326/327`); `selection_path`
matches (`Data` contains `ntds.dit`) → rule fires on all 4.

## Negative (must not match)

Same ESENT/NTDS event family, but for an unrelated database file (not
`ntds.dit`) — e.g. a routine online defragmentation/consistency-check
event that also uses these event IDs:

```
Channel:       Application
Provider_Name: ESENT
EventID:       326
Data:          ... C:\Windows\NTDS\edb.chk ...
```

`application` and `selection_eid` match, but `Data` does not contain
`ntds.dit` → `selection_path` does not match → rule does not match.

## Negative (must not match)

Correct provider and path, but an EventID outside the four this rule
tracks:

```
Channel:       Application
Provider_Name: ESENT
EventID:       102
Data:          ... C:\Windows\NTDS\ntds.dit ...
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
Data:          ... C:\Windows\NTDS\ntds.dit ...
```

`selection_eid` does not match (`Provider_Name` isn't `ESENT`) → rule
does not match.

## Known limitation (documented in `description`)

Because this rule now matches the same flat `Data|contains: ntds.dit`
selector as the builtin `Ntdsutil Abuse` rule, it produces duplicate
detections alongside it wherever both are loaded — it adds no detection
coverage the builtin doesn't already provide. See the investigation
report's assessment of whether to keep or remove this rule.
