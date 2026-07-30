# Endpoint Investigation

## Endpoint

**Requested label:** `SAMPLE-EVTX-01`
**Evidence path:** `C:\Users\omery\scratch\hayabusa-sample-evtx\EVTX-ATTACK-SAMPLES`

**Important scoping note:** this evidence path is **not** a single endpoint's log export. It is the public **EVTX-ATTACK-SAMPLES** corpus — 278 discrete `.evtx` files, each a small, independently-captured demonstration of one ATT&CK technique, spanning **~24 distinct synthetic hostnames** (`MSEDGEWIN10`, `IEWIN7`, `PC01-04.example.corp`, `DC1.insecurebank.local`, `01566s-win16-ir.threebeesco.com`, etc.) and a **~4-year capture-date range** (2018-11-06 to 2023-01-24). It is a detection-testing/training corpus, not a real incident on a real host. Findings below are reported per-artifact/per-host, not as a single continuous attack timeline, and severity should be read as "this technique is realistically detectable," not "this host was actually compromised."

The heaviest concentration of chained, multi-technique activity is on host **`MSEDGEWIN10`**, which appears to host an Atomic Red Team test-harness run (evident from `C:\AtomicRedTeam\` paths and `atomics\Txxxx\` file references throughout).

## Timeline

Two dense clusters stand out on `MSEDGEWIN10` (all times local, +01:00 in source data):

- **2019-07-19, 15:49–16:11** — a single PowerShell-launched sequence performing, in order: SAM/SYSTEM/SECURITY registry hive export (`reg save`), NTDS.dit + SYSTEM hive copy from a VSS shadow copy, LSASS memory dump via `procdump.exe`, and shadow-copy/backup-catalog deletion (`vssadmin`, `wbadmin`). This reads as a scripted "credential access + anti-forensics" technique-test chain, not organically paced attacker behavior.
- **2019-10-17** — UAC-bypass technique tests (CMSTP / ICMLuaUtil) launching a masqueraded `WINWORD.exe` (`test.exe`) via a DllHost COM object.
- **2020-10-15 to 2020-10-23** — a separate cluster including Trickbot/Pikabot-style process-hollowing activity (`wermgr.exe` spawned by `rundll32.exe` loading a DLL from `c:\temp\`).

Independently, on **`DC1.insecurebank.local`**, Application-log ESENT events (326 → 325 → 327, 2019-11-26 23:55:00–02) record an `ntdsutil` "Install From Media" (IFM) snapshot/backup operation writing `ntds.dit` to both a VSS snapshot path and a user-writable path (`C:\Users\bob\Desktop\test\Folder\ntds\...`) — a separate, standalone NTDS.dit-extraction technique sample, unrelated to the `MSEDGEWIN10` cluster.

Full corpus-wide timeline correlation (all 278 files) was not performed — see Recommendations.

## Findings

Source: `scan_evtx` (min_level=medium) + `hayabusa_search` + `hayabusa_logon_summary`. The scan itself matched **1,574 detections** across the corpus; the bounded result set returned the top 200 (2 of ~24 hosts, `MSEDGEWIN10`/`IEWIN7`, dominate that slice — see Recommendations for how to get the full picture).

**Critical**
- **Sticky Key–Like Backdoor Usage – Registry** (7 hits, `MSEDGEWIN10`, all within ~18s on 2019-07-19): IFEO `Debugger` value set to `cmd.exe` on every accessibility binary Windows exposes at the logon screen — `osk.exe`, `sethc.exe`, `utilman.exe`, `magnify.exe`, `narrator.exe`, `DisplaySwitch.exe`, `atbroker.exe`. A pre-auth SYSTEM-shell backdoor reachable from the Windows logon screen.

**High**
- **Dumping of Sensitive Hives Via Reg.EXE** (7 hits): `reg save HKLM\SAM sam.hive` / `HKLM\SYSTEM` / `HKLM\SECURITY`, confirmed via `hayabusa_search` with full process lineage (`powershell.exe` → `cmd.exe` → `reg.exe`).
- **NTDS.dit / SYSTEM hive copy from VSS shadow copy** ("Suspicious Process Patterns NTDS.DIT Exfil", "Copying Sensitive Files with Credential Data"): `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Extract\ntds.dit`.
- **LSASS memory dump**: `procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp`, plus a corroborating medium-severity Sysmon EID 10 process-access record (PowerShell → `lsass.exe`, access mask `0x1010`).
- **Shadow-copy / recovery-catalog deletion**: `vssadmin.exe delete shadows /all /quiet`, `wbadmin.exe delete catalog -quiet` — anti-forensics.
- **Boot configuration tampering**: `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` / `recoveryenabled no`.
- **UAC bypass (CMSTP / ICMLuaUtil)**: masqueraded Office binary (`test.exe`, PE description "Microsoft Office Word") launched via DllHost COM object, sideloading `wwlib.dll` from a non-standard path.
- **Process hollowing / masquerading** ("Trickbot Malware Activity", "Potential Pikabot Hollowing Activity", 2020-10-20): `wermgr.exe` spawned by `rundll32.exe c:\temp\winfire.dll,DllRegisterServer`.
- **Regsvr32 abuse** (T1117 Atomic tests): execution from a non-standard path, and a `regsvr32 /i:...scrobj.sct` → `calc.exe` proof-of-concept child process (Squiblysort/registration-free COM scripting).
- **NTDS.dit IFM extraction via ntdsutil** (`DC1.insecurebank.local`, Application/ESENT log, EventIDs 325/326/327) — see Detection Coverage below; a matching rule exists but appears not to have fired (field-mapping issue, not absence of a rule).

**Authentication activity** (`hayabusa_logon_summary`): 44 distinct successful-logon groupings, 1 failed logon (`IEUser` interactive, `MSEDGEWIN10`). Nothing anomalous stands out — mostly machine-account network logons (Type 3) and expected service logons (Type 5); a handful of `ANONYMOUS LOGON` Type-3 logons appear against `01566s-win16-ir.threebeesco.com` and `PC02.example.corp`, which is at minimum worth a SMB-null-session check but is common in this kind of test corpus (null-session/enumeration technique samples) rather than evidence of a real breach.

**Persistence indicators**: multiple Run-key / Autorun registry modifications, an `AppInit_DLLs` addition, a startup-folder file write, and scheduled-task creation via `schtasks.exe` from a suspicious path — all on `MSEDGEWIN10`, consistent with the same technique-test corpus rather than a single persistence campaign.

## ATT&CK Techniques

Techniques with confirmed firing detections in this corpus (Sigma rule tags plus explicit `Txxxx`/`atomics\Txxxx\` markers left by the Atomic Red Team harness itself):

| Technique | Description |
|---|---|
| T1003.002 | SAM/SECURITY/SYSTEM registry hive dump via `reg.exe` |
| T1003.003 | NTDS.dit extraction (VSS copy **and**, separately, `ntdsutil` IFM) |
| T1003.001 | LSASS memory dump via `procdump.exe` |
| T1546.008 / T1546.012 | Accessibility-feature / IFEO Debugger backdoor ("Sticky Keys") |
| T1490 | Inhibit System Recovery (`vssadmin`, `wbadmin delete catalog`) |
| T1548.002 | UAC bypass (CMSTP, ICMLuaUtil) |
| T1055 | Process injection / hollowing (`mavinject`, Trickbot/Pikabot-style) |
| T1117 / T1218.010 | Regsvr32 signed-binary proxy execution |
| T1197 | BITS Jobs (suspicious downloads via `bitsadmin`) |
| T1216 | Signed script proxy execution (`pubprn.vbs`) |
| T1220 | XSL script processing (WMIC "SquiblyTwo") |
| T1036 | Masquerading (renamed binaries: `Flash_update.exe` → `NvSmart.exe`, `test.exe` as Office) |
| T1547.001 / T1112 | Registry Run-key / Autorun persistence |

## Detection Coverage

| Technique | Status | Rule |
|---|---|---|
| T1003.002 (SAM/SECURITY/SYSTEM hive dump) | **Covered, fired correctly** | `Dumping of Sensitive Hives Via Reg.EXE` (builtin) |
| T1003.001 (LSASS dump via Procdump) | **Covered, fired correctly** | `Potential LSASS Process Dump Via Procdump` + `Potential Credential Dumping Attempt Via PowerShell` (builtin) |
| T1003.003 (NTDS.dit via VSS copy) | **Covered, fired correctly** | `Suspicious Process Patterns NTDS.DIT Exfil` (builtin) |
| T1003.003 (NTDS.dit via `ntdsutil` IFM, Application/ESENT log) | **Covered, fired correctly by the builtin rule — the "fix" in commit `8e648e7` was based on an incorrect root-cause diagnosis and does not work.** See correction below. | `Ntdsutil Abuse` (builtin, `sigma\builtin\application\esent\win_esent_ntdsutil_abuse.yml`) |
| T1546.008/.012 (Sticky Keys / IFEO backdoor) | **Covered, fired correctly** | `Sticky Key Like Backdoor Usage - Registry` (builtin) |
| T1490 (Shadow copy / catalog deletion) | **Covered, fired correctly** | `Shadow Copies Deletion Using Operating Systems Utilities` (builtin) |
| T1548.002 (UAC bypass) | **Covered, fired correctly** | `UAC Bypass via ICMLuaUtil`, `CMSTP UAC Bypass via COM Object Access` (builtin) |
| T1055 (Process hollowing/injection) | **Covered, fired correctly** | `Trickbot Malware Activity`, `Potential Pikabot Hollowing Activity`, `Rare Remote Thread Creation By Uncommon Source Image` (builtin) |

## Correction (2026-07-29 re-verification)

**The T1003.003/`ntdsutil` "false negative fix" from commit `8e648e7` was wrong.** Re-running this investigation and directly testing against the real evidence file (`dc_applog_ntdsutil_dfir_325_326_327.evtx`) showed:

- The **builtin** `Ntdsutil Abuse` rule (`Data|contains: ntds.dit`, the flat, non-indexed field) **fires correctly on all 4 events** (EventIDs 325/326/327×2) when scanned with hayabusa's default rule set. It was never actually broken — hayabusa's `contains` modifier against the `Data` field checks across all of the event's indexed `Data[N]` values, not just a single combined string, so the flat-field match already works.
- The custom replacement rule that had matched `Data[1]|contains` through `Data[8]|contains` as if those were real, independently-addressable Sigma field names **fired zero times** against the same evidence file. `Data[1]`…`Data[8]` are not real field keys hayabusa exposes to its Sigma engine — they are cosmetic labels hayabusa's CSV/search renderer invents when it prints an unnamed, multi-value `Data` field for human readability (visible in `AllFieldInfo`/`Details` output). Confirmed by isolating both forms as minimal standalone rules and running each against the real evtx: `Data|contains: ntds.dit` → 4/4 hits, `Data[5]|contains: ntds.dit` → 0/4 hits.
- `validate-rule.py` (this project's rule-standards linter) never caught this because it only checks rule *metadata* (ATT&CK tags, `level`, `falsepositives`, presence of a `.testcases.md` sibling) — it never runs the rule against hayabusa or real event data. The rule's own `.testcases.md` is a hand-written prose walkthrough of intended logic, not an executed test, so it also didn't catch that `Data[N]` isn't a matchable field.

**Resolution:** the custom rule was first corrected to match `Data|contains: ntds.dit` (same selector as the builtin) and re-verified firing 4/4 on the real sample, but at that point it was a functional duplicate of the builtin `Ntdsutil Abuse` rule — same event family, same selection logic, same 4/4 result, no added coverage. `rules/ntds_dit_extraction_via_ntdsutil_esent.yml` and its `.testcases.md` were deleted rather than kept as a no-value duplicate; this technique's coverage relies solely on the builtin rule going forward.

### Follow-up: the same bug class found in three more custom rules

Auditing the remaining custom rules in `rules/` for the same failure mode (a structural condition that guarantees zero detections regardless of real activity) surfaced a related but distinct bug, plus one more confirmed-broken-and-duplicate case:

- **`authentication_package_lsa_persistence.yml`** and **`sensitive_privilege_use_backup_restore.yml`** both had **no `Channel` selector anywhere in their detection logic** — unlike the `Data[N]` bug (a fake field name), this caused hayabusa's channel filter to exclude every input file and disable the rule entirely before any field matching even happens, confirmed via `hayabusa -v` output (`Evtx files loaded after channel filter: 0`, reproduced even when scanning the full 278-file corpus). Every other rule in this project's set, builtin and custom, explicitly declares a `Channel` gate; these two didn't. Fixed by adding `registry_event: {Channel: Microsoft-Windows-Sysmon/Operational}` and `security: {Channel: Security}` blocks respectively, matching this project's established convention. Re-verified: the auth-package fix now fires 1/1 against a real Sysmon EventID 13 sample (`\CurrentVersion\Run\360v` in `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, retargeted to prove the fix, since no real Authentication Packages sample exists in this corpus); the privilege-use fix now survives the channel filter (52/278 files enabled) but has no real EventID 4673 sample in this corpus to confirm an actual positive match — only the noisier EventID 4672/4703 privilege-grant events were found.
- **`registry_save_sam_hive_reg_exe.yml`** had the identical missing-`Channel` bug (confirmed 0 hits in isolation against its own target evidence, `reg save HKLM\SAM sam.hive` on `MSEDGEWIN10`) **and** its premise was wrong: its description claimed "no active detection for this behavior out of the box" after two specific builtin rules were confirmed deprecated, but missed a third, non-deprecated builtin — `Dumping of Sensitive Hives Via Reg.EXE` (`sigma\builtin\process_creation\proc_creation_win_reg_dumping_sensitive_hives.yml`, `status: test`) — which already covers this exact technique and is almost certainly what actually produced the original "7 hits" finding above, not this custom rule. Deleted rather than fixed, same reasoning as the ntdsutil case: a working builtin already exists.

**Rules checked and found sound:** `admin_share_access_smb.yml` (re-confirmed firing 3/3 on real EID 5140 evidence); `remote_registry_service_started.yml` (its `Channel` key is embedded inline in the selection block rather than a separate mapping block, but confirmed via `-v` that hayabusa's channel filter still honors it once matching-channel data is in scope — no real sample to confirm an actual positive match, but not structurally broken).

**Separate finding, since fixed (2026-07-30):** `admin_share_write_access_smb.yml` used an exact-match `AccessMask: '0x2'`, copied from the identical builtin rule it's modeled on, but every real EID 5145 write event in this corpus carries a combined mask (e.g. `0x120196`) that never equals literal `0x2` — confirmed via `hayabusa_search` that no event in the entire corpus has an exact `0x2` mask. Follow-up investigation confirmed: Sigma has no bitwise-AND modifier (checked against the current Sigma spec's full modifier list), and `Yamato-Security/hayabusa-rules` `main` (freshly fetched, byte-identical diff against the installed copy) has not addressed this in the builtin rule either — so this is a real, upstream-unfixed gap, not a rule-writing mistake unique to this project. Fixed by replacing the exact match with `AccessMask|re: '[2367abABEF]$'`, a low-nibble bit-1 test matching the technique this project's own installed builtin `win_security_ad_user_enumeration.yml` already uses for an analogous single-bit check (`AccessMask|endswith` with wildcard hex-digit patterns). Re-verified against the real corpus: 0 hits before the fix, **14 hits after** (10 with real combined masks like `0x120196` — including a newly-surfaced `C$` write via Backup-Operator-privilege abuse on `01566s-win16-ir.threebeesco.com` — and 4 with the bare `0x2` the original rule already caught), with read-only (`0x1`) and non-write combined masks (`0x100081`) correctly still excluded.

**Process takeaway:** five of the seven custom rules that existed in this project's `rules/` directory at the start of this investigation (the ntdsutil rule plus the six covered above) shipped with a structural defect that `validate-rule.py` cannot catch (it checks YAML metadata shape only, never runs a rule against real data) and that hand-written `.testcases.md` prose didn't catch either (it describes intended logic, not executed results). Every fix in this investigation — including this one — was found and confirmed by actually running the rule against real `.evtx` data via `hayabusa_csv_timeline`/`-v`, not by reading the YAML. Recommend this become a standard step before marking any new custom rule "done."

### Follow-through on the process takeaway: CI enforcement, and an unrelated CI break found and fixed along the way (2026-07-30)

Acting on the process takeaway above, `validate-rule.py`'s existing metadata checks (ATT&CK tag, valid `level`, real `falsepositives`, a `.testcases.md` sibling) were wired into CI as a new `validate-rules` job in `.github/workflows/test.yml`, so a rule failing any of those checks now fails the build automatically instead of relying on someone remembering to run the script by hand. This does not yet close the bigger gap identified above (an execution-based "does it actually fire" check is still manual, not automated) — deliberately scoped this way, as a smaller first step.

Checking the resulting CI run surfaced a second, unrelated problem: `pytest` and `lint` (mypy) had already been failing on every commit since `8a047ec` (2026-07-29), well before this session's rule fixes — `pyproject.toml`'s `mcp>=1.2.0` dependency had no upper bound, and CI had started resolving the newly-published `mcp==2.0.0`, which removes `mcp.server.fastmcp` entirely as part of a breaking API redesign (`FastMCP` replaced by `mcp.server.mcpserver.MCPServer`, package governance transferred to LF Projects). Confirmed by installing `mcp==2.0.0` in an isolated venv: no `fastmcp` module anywhere in it, while the latest 1.x release (`1.29.0`) still has it. Fixed by pinning `mcp>=1.2.0,<2.0.0` in `pyproject.toml` — restores a working CI install without migrating this project's code to the new 2.x API, which would be a separate, non-trivial follow-up. CI is green again as of this fix (`validate-rules`, `pytest` 3.10/3.11/3.12, and `lint` all passing).

## Recommendations

1. **Re-run with a higher `max_results`/`max_rows` (or page through `rule_filter`) before treating any "top findings" list from this corpus as complete.** The 200-row bound on `scan_evtx` hid detections from ~22 of ~24 hosts entirely (only `MSEDGEWIN10`/`IEWIN7` surfaced); `hayabusa_log_metrics` similarly only covered 200/278 files. Neither omission changes the *qualitative* findings above (which were confirmed via targeted `hayabusa_search` calls), but a corpus-wide detection count or "which hosts had zero detections" claim would need the fuller pull.
2. **Channel coverage gaps observed in this evidence set** (informational, not necessarily gaps in your actual environment — this is a synthetic corpus): thin-to-absent native PowerShell Script Block Logging (4104), Task Scheduler Operational, WMI-Activity, DNS, and System-channel coverage. Techniques whose primary evidence normally lives in those channels are represented here (if at all) only via Sysmon side effects.
3. **Two data-quality items to confirm before citing file counts elsewhere**: `UACME_59_Sysmon.evtx` appears twice in `log-metrics` output with byte-identical metadata (confirm it isn't duplicated on disk), and normalize timestamps to UTC before any further cross-file correlation (source data mixes `+00:00`/`+01:00` for the same host).
