# False Positive Patterns

Every rule's `falsepositives:` field must list realistic, specific conditions that
would cause benign activity to match — not `Unknown`, not an empty list, and not
omitted entirely. This document catalogs the recurring categories of false positive
so they're easier to recognize and describe precisely when writing a new rule.

A good false-positive entry names **what** triggers it and, where practical, **how
to narrow it away** (a specific path, publisher, or command-line pattern) rather
than just noting that FPs exist in the abstract.

## Weak vs. strong false-positive descriptions

| Weak (don't write this) | Strong (write this instead) |
|---|---|
| "Unknown" | Omit only if you've genuinely investigated and found none — see below. |
| "Some admin tools" | "SCCM/ConfigMgr client (`ccmexec.exe`) performing scheduled inventory scans" |
| "Antivirus" | "Microsoft Defender (`MsMpEng.exe`) real-time scanning engine, and CrowdStrike Falcon sensor (`CSFalconService.exe`)" |
| "May cause false positives" | "Triggers on any `rundll32.exe comsvcs.dll,MiniDump` call regardless of target PID, including legitimate dumps of crashed non-LSASS applications" |

If you genuinely cannot identify *any* realistic false positive after checking
common admin/EDR/backup tooling against the detection logic, that itself is a red
flag worth raising in review rather than silently shipping an empty-feeling list —
it usually means either the logic is narrower than you think (good) or you haven't
looked hard enough (needs more work).

## Common false-positive categories

### 1. Security/EDR tooling doing the same thing attackers do

Defensive tools frequently perform actions that are indistinguishable, at the
single-event level, from the attack technique being detected — reading LSASS
memory, enumerating processes, opening privileged handles, making outbound
connections to update servers.

**How to describe it:** name the specific product/process (`MsMpEng.exe`,
`CSFalconService.exe`, `SentinelAgent.exe`), and note that the exact set is
environment-dependent, so a filter list in the rule is a starting point that
needs local tuning, not a complete allow-list.

### 2. IT administration and deployment tooling

SCCM/ConfigMgr, Intune, Group Policy scripts, Ansible/Puppet/Chef agents, and
similar tools legitimately perform actions that overlap with attacker tradecraft:
remote command execution, scheduled task creation, registry modification, service
installation.

**How to describe it:** name the tool and the specific legitimate workflow (e.g.
"software deployment via SCCM's `execmgr.exe` creating a scheduled task to run an
installer at the next maintenance window") rather than just "deployment tools."

### 3. Built-in Windows/OS behavior

Some benign OS behavior looks like the attack pattern by construction — Windows
Error Reporting generating a crash dump of a faulted process, `svchost.exe`
hosting a service that touches a sensitive resource, `wininit.exe`/`services.exe`
performing normal service-control operations, scheduled maintenance tasks that
ship with the OS.

**How to describe it:** name the specific OS component/binary and the normal
condition that triggers it (e.g. "WerFault.exe generating a dump after lsass.exe
itself crashes, rather than an external process reading its memory").

### 4. Developer/power-user tools with legitimate dual use

Tools like `procdump`, `psexec`, `certutil`, `rundll32`, `mshta`, `regsvr32`, and
scripting engines (PowerShell, WSH) are LOLBins/sysadmin staples with real
legitimate uses (debugging, software installers, certificate operations) as well
as offensive ones.

**How to describe it:** describe the legitimate workflow specifically enough that
it's distinguishable in principle (e.g. "developers using `procdump.exe` to capture
a crash dump of their *own* application for debugging, typically run manually from
an interactive console session rather than a script/service context") even if the
current rule logic can't yet make that distinction — this documents a known
limitation and a direction for future tuning.

### 5. Backup, monitoring, and vulnerability-scanning agents

HIDS/FIM agents, backup software (Veeam, Commvault), and vulnerability scanners
often enumerate files, processes, or registry keys system-wide, which can trigger
rules built around "unusual" enumeration or access patterns.

**How to describe it:** name the category and, if known, the specific product in
use in the target environment, and note the activity is typically scheduled
(recurring at consistent intervals) which can help distinguish it from ad hoc
attacker activity in the accompanying description.

### 6. Structural/logical limitations of the detection itself

Some false positives aren't about a specific tool at all — they're a consequence
of what the detection logic can and cannot see. For example, a command-line-based
rule that matches on a numeric PID argument can't verify which process that PID
actually belongs to; a rule scoped to a process name can be evaded or produce FPs
from any other process sharing that name.

**How to describe it:** state the limitation directly (e.g. "cannot distinguish
which process the numeric PID argument targets, so any invocation matching this
command-line pattern fires regardless of the actual target process") and, where
possible, suggest the correlation step needed to resolve it (e.g. "confirm the
target PID against a process list for the same timestamp before escalating").
This is different from the tool-specific categories above but just as important
to document — see `references/example-rules/lsass_memory_access.yml`'s
`falsepositives:` field for a worked example combining several of these categories.

## Checklist when writing `falsepositives:`

- [ ] At least one entry names a specific, real-world source (tool, process, or
      workflow) rather than a vague category.
- [ ] If the rule has a known structural blind spot (category 6 above), it's
      called out explicitly, not left implicit.
- [ ] Entries that depend on environment-specific tooling say so, so the next
      person tuning the rule knows to extend rather than replace them.
- [ ] Nothing in the list is just the literal string `Unknown` or an empty list.
