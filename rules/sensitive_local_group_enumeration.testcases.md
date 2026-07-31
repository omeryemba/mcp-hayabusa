# Test cases: sensitive_local_group_enumeration

Both the positive and negative cases below are backed by real Event ID
4799 records found in the EVTX-ATTACK-SAMPLES corpus
(`Discovery/4799_remote_local_groups_enumeration.evtx`), from the same
host/actor/session (`jbrown` on `01566s-win16-ir.threebeesco.com`,
2023-01-24) — isolating exactly the `TargetUserName` field this rule's
`selection` keys on. A second, independent source file
(`Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx`)
corroborates the same `Administrators`/EventID 4799 pattern from an
unrelated host/session.

Fixture files have not yet been vendored under `tests/fixtures/evtx/` —
the `fixture:` names below are the filenames these cases will use once
that's done; until then, `validate-rule-execution.py` will report them
as `skipped` (missing fixture), not `pass`.

## Positive (must match)

Security Event ID 4799, enumeration of the built-in `Administrators`
group — the classic "who has local admin" recon step:

```
Channel:          Security
EventID:          4799
CallerProcessName: C:\Windows\System32\net1.exe
SubjectUserName:  jbrown
TargetDomainName: Builtin
TargetSid:        S-1-5-32-544
TargetUserName:   Administrators
```

```yaml
fixture: sensitive_local_group_enumeration.evtx
expect: fires
min_hits: 1
```

Real record: `Discovery/4799_remote_local_groups_enumeration.evtx`,
EventRecordID 3819707. `security` matches (`Channel: Security`);
`selection` matches (`EventID: 4799`, `TargetUserName` is
`Administrators`, one of the four selected groups) → rule fires.

## Positive (must match, prose only — not a separate execution case)

The same source file also contains a second real positive: EventRecordID
3819771, identical shape but `TargetUserName: Remote Desktop Users`
(SID `S-1-5-32-555`) — confirms the selection list isn't accidentally
scoped to `Administrators` alone. Not given its own `fixture:`/`expect:`
block since it exercises the same logic as the case above against the
same fixture file; documented here for completeness.

## Negative (must not match)

Security Event ID 4799, enumeration of the default, non-privileged
`Users` group — same host, same actor, same session as the positive
case above, isolating the `TargetUserName` field:

```
Channel:          Security
EventID:          4799
CallerProcessName: -
SubjectUserName:  jbrown
TargetDomainName: Builtin
TargetSid:        S-1-5-32-545
TargetUserName:   Users
```

```yaml
fixture: sensitive_local_group_enumeration__negative.evtx
expect: no_fire
```

Real record: `Discovery/4799_remote_local_groups_enumeration.evtx`,
EventRecordID 3819788. `security` matches, but `selection` does not
(`TargetUserName: Users` is not in the selected group list) → rule does
not fire.

## Negative (must not match, prose only)

Event ID 4798 ("A user's local group membership was enumerated") against
the same host — a per-*user* enumeration, not a per-*group* one; this
rule intentionally scopes to 4799 only:

```
Channel:          Security
EventID:          4798
CallerProcessName: C:\Windows\System32\net1.exe
SubjectUserName:  IEUser
TargetUserName:   Administrator
```

`selection` does not match (`EventID` is `4798`, not `4799`) → rule does
not fire. (Real record available for this shape:
`Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx`,
EventRecordID 10089, but not wired into an execution case here since it
isn't this rule's positive/negative pair.)

## Negative (must not match, prose only)

Otherwise-matching event content, but from a channel other than the one
this rule is scoped to — confirms the `security` channel gate actually
constrains matching rather than being decorative (the lesson from this
project's `dee2e8b` incident, where a missing `Channel` gate silently
disabled a rule entirely):

```
Channel:          Application
EventID:          4799
TargetUserName:   Administrators
```

`security` does not match (`Channel` isn't `Security`) → rule does not
fire.

## Known limitation (documented in `falsepositives`)

This event only shows that a group's membership was queried and by
which account/process — it does not indicate the query itself was
unauthorized. `SubjectUserName`/`CallerProcessName` should be correlated
against expected admin accounts and known tooling (MMC snap-ins, SCCM,
vulnerability scanners) before escalating.
