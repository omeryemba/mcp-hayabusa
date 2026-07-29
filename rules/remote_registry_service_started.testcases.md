# Test cases: remote_registry_service_started

## Positive (must match)

System Event ID 7036, the Remote Registry service transitioning to
running — a precondition for remote SAM/SECURITY hive access over the
winreg RPC interface:

```
EventID:       7036
Channel:       System
Provider_Name: Service Control Manager
param1:        Remote Registry
param2:        running
```

`selection` matches all four fields → rule fires.

## Negative (must not match)

Event ID 7036 for an unrelated service starting:

```
EventID:       7036
Channel:       System
Provider_Name: Service Control Manager
param1:        Windows Update
param2:        running
```

`selection` does not match (`param1` doesn't contain `Remote Registry`)
→ rule does not match.

## Negative (must not match)

Remote Registry stopping rather than starting — only the running
transition is the precondition of interest:

```
EventID:       7036
Channel:       System
Provider_Name: Service Control Manager
param1:        Remote Registry
param2:        stopped
```

`selection` does not match (`param2` is `stopped`, not `running`) →
rule does not match.

## Known limitation (documented in `falsepositives`/description)

`param1`/`param2` are localized display strings — this rule as written
only covers a default English-language OS install. A non-English system
would need additional localized values added, the same caveat the
vendored `win_system_defender_disabled.yml` rule documents for this
exact event ID.
