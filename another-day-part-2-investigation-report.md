# Investigation Report

## Another Day, Part Two

Nimbus Health // Security Operations · Case NH-INC-2026-0528

---

# Part A, Core

## 1. Front matter

| **Field**            | **Value**                                                                     |
| -------------------- | ----------------------------------------------------------------------------- |
| Report title         | Another Day, Part Two, Investigation Report, NH-INC-2026-0528                 |
| Case reference       | NH-INC-2026-0528 *(analyst-assigned; no SOC case ID was issued for this hunt)* |
| Author               | [ANALYST], SOC / Cyber Range Operations (on shift)                            |
| Version              | 1.0                                                                           |
| Date issued (UTC)    | 2026-08-15                                                                    |
| Classification / TLP | TLP:AMBER, internal + trusted-party distribution                              |
| Distribution         | SOC, Clinic IT, HR, Legal/Privacy, Incident Response                          |
| Related case         | NH-INC-2026-0311 (*Just Another Day*, March 2026, same estate, separate actor activity) |

### Revision history

| **Version** | **Date (UTC)** | **Author** | **Change**                                                           |
| ----------- | -------------- | ---------- | -------------------------------------------------------------------- |
| 1.0         | 2026-08-15     | [ANALYST]  | Initial issue. Investigation complete, compromise confirmed, exfiltration confirmed. |

### Note on time

**The Sentinel portal rendered results in browser-local time (UTC-7) while `TimeGenerated` filters evaluate in UTC.** This is not cosmetic: narrow UTC windows built around locally-displayed timestamps returned zero rows twice during this investigation. Times in this report are given as **displayed (UTC-7)**, with the UTC equivalent being +7 hours; the operator session displayed as 28 May 18:28–18:57 is 29 May 01:28–01:57 UTC. The workspace timezone setting was not independently confirmed and is listed in Appendix D (D1).

---

## 2. Executive summary

**This is a confirmed external breach with confirmed data theft, and the new starter is the victim, not the cause.** On 28 May 2026 an outsider signed in to a Nimbus Health IT workstation from the public internet using the correct password for a technician who had been employed for one month. Over thirty-one minutes they looked around, listed the staff of the HR department, opened an HR file the account had no business opening, collected three documents into a folder named to look like routine support work, compressed them, and carried the archive out through the remote-desktop connection itself. The intrusion was uninterrupted and was found by proactive hunting, not by an alert.

**Exposure.** Three files left the estate: an HR access-request queue, an individually identified employee record, and a set of access-review notes. This is confirmed exfiltration, not suspected access. The archive was observed being written to a drive belonging to the attacker's own computer. Legal and Privacy must begin a notification assessment immediately, and the contents of the employee record must be inspected to determine whether occupational-health material is inside, which would change both the regulator and the clock.

**How it happened, in one line.** Everything the attacker needed was published. The technician's name, employer, role and personal email address were on a public professional profile. That email address appears in three breach corpora, one of which is a 2025 credential-stuffing collection of plaintext password pairs. An internal Nimbus support document naming the internet-facing workstation, its public address, and the instruction to use domain credentials had been indexed into a public document cache. The attacker did not need to research this organisation; they needed to read it.

**What has to change.** No exploit, no malware, no privilege escalation, and no persistence appear anywhere in this incident. Remote Desktop was reachable from the open internet and required only a password. Multi-factor authentication would have stopped this at the first minute regardless of how the password was obtained, and disabling drive redirection would have removed the exfiltration channel even if the session had succeeded. The clinic's own framing, a curious new starter poking around, is contradicted by the source addresses: the account authenticated from two unrelated foreign public addresses, one of which had to guess its way in.

---

## 3. Scope and data sources

| **Data source**                                     | **Platform**                     | **Period examined**      | **Confidence in coverage**                                        |
| --------------------------------------------------- | -------------------------------- | ------------------------ | ----------------------------------------------------------------- |
| DeviceLogonEvents (authentication, logon type, source address) | law-cyber-range (Sentinel / MDE) | 2026-05-25 to 2026-05-31 | High; external and internal sources both present                  |
| DeviceProcessEvents (execution + full command line) | law-cyber-range                  | 2026-05-25 to 2026-05-31 | High; command lines populated throughout                          |
| DeviceFileEvents (create, modify, rename, delete)   | law-cyber-range                  | 2026-05-25 to 2026-05-31 | High on nh-wks-it-01                                              |
| DeviceEvents (service install, scheduled task, account changes) | law-cyber-range      | 2026-05-25 to 2026-05-31 | Medium; queried for persistence indicators only                   |
| Open-source artefacts (public profile, breach-exposure report, cached support document, role matrix) | Non-SIEM, supplied in evidence bag | Retrieved 30 Apr – 19 May 2026 | High as artefacts; attribution of the specific credential is assessed, not proven |

### Evidence verification

Every value in this report was re-read off the query result it is attached to. Two errors during the investigation are recorded here because both are generalisable:

1. **Host filtering.** `DeviceName == "nh-wks-it-01"` returned nothing. MDE stores the FQDN (`nh-wks-it-01.corp.nimbushealth.com`), so `has` is required. An exact-match filter silently produces an empty result that reads as a negative finding.
2. **Path citation.** The exfiltration destination was initially cited with the filename appended to the folder path. `FolderPath` in `DeviceFileEvents` carries the directory only. Reconstructing a value from a truncated grid cell rather than expanding the row produced a wrong citation of an otherwise correct finding.

Scope was bound to `nh-wks-it-01` and 25–30 May 2026 on every query except the two negative tests against nh-fs-01. The workspace is shared and holds a separate March 2026 incident on the same estate (NH-INC-2026-0311); that activity is excluded by the time bind and is out of scope.

### Gaps and blind spots

- **nh-dc-01 was never examined.** The initial account-scoped sweep showed 26 `LogonSuccess` events for `m.reed` on the domain controller inside the window. These were not characterised by logon type or source. They are most likely Kerberos/authentication traffic incidental to domain membership, but that is an assumption, not a finding. **This is the single largest gap in the report.**
- **Ten nh-fs-01 network logons carry no source address.** 29 of 39 resolve to 10.1.0.233 (nh-wks-it-01). The remaining 10 have a blank `RemoteIP` and were not attributed.
- **The clinical share was never checked.** No query was run against `\\NH-FS-01\Clinical`. In a healthcare setting this cannot be left as an assumption; see Appendix D, D4.
- **No alert-status query.** `SecurityAlert` and `SecurityIncident` were not queried. The claim that no alert fired is inferred from the absence of an alert-driven referral.
- **The scheduled-task/registry process sweep did not execute.** A syntax error (two queries concatenated in the editor) caused it to fail, and it was not re-run. The no-persistence conclusion rests on `DeviceEvents` alone, which is sufficient but not complete; see Appendix D, D2.
- **Archive contents were never inspected.** The three staged filenames are known; the data elements inside them are not. This determines the notification obligation.
- **The specific breach corpus is an assessment.** Two of the three exposures contain plaintext credentials. Attribution to the 2025 collection rests on recency and fitness for purpose, not on a matched password. No telemetry can close this.
- **No network-flow review.** `DeviceNetworkEvents` was not swept. In this incident that is defensible, because the exfiltration channel was file-based and identified, but it means a second, parallel channel would not have been seen.

---

## 4. Timeline

All times 28 May 2026, displayed local (UTC-7); add 7 hours for UTC.

| **Time**       | **Event**                                                                                       | **Source**          | **Evidence ref** |
| -------------- | ------------------------------------------------------------------------------------------------- | ------------------- | ---------------- |
| 30 Apr 2026    | Internal remote-support reference indexed into a public document cache, naming NH-WKS-IT-01, 135.237.163.62, and "use domain credentials when prompted". | OSINT artefact 03   | F1               |
| 28 Apr 2026    | m.reed start date per role matrix; IT Support Technician, Standard User.                          | OSINT artefact 04   | F1               |
| 19 May 2026    | Breach-exposure lookup against mason.reed@hotmail.com returns three corpora.                      | OSINT artefact 02   | F2               |
| 25–29 May      | `admin_maint.ps1` executes hourly under `svchost.exe`; 78 Batch logons across the window.         | DeviceProcessEvents | N1, B-6          |
| 18:26:21       | First failed logon for m.reed from 116.45.242.115.                                                | DeviceLogonEvents   | F3, B-1          |
| 18:28:22–18:28:23 | Two `Network` logon successes from 116.45.242.115 after three failures.                        | DeviceLogonEvents   | F3, B-1          |
| 18:28:27       | `RemoteInteractive` session established on nh-wks-it-01 from 116.45.242.115.                      | DeviceLogonEvents   | F3, F4           |
| 18:28:27–18:29 | First-logon profile provisioning: `userinit`, `explorer`, `sihost`, `taskhostw`, `ctfmon`, `unregmp2 /FirstLogon`, `ie4uinit -UserConfig`, `smartscreen`, `TSTheme`, `rdpclip`. Nineteen per-user services registered under the machine account. | DeviceProcessEvents, DeviceEvents | F5, N1 |
| 18:29          | OneDrive first-run and update sequence under `onedrivesetup.exe`.                                 | DeviceFileEvents    | F6               |
| 18:30:09       | `cmd.exe` console opened. No shell existed in the session before this point.                      | DeviceProcessEvents | F5               |
| 18:30:14 → 18:31:04 | Orientation burst: `whoami`, `hostname`, `ipconfig /all`, `whoami /groups`.                  | DeviceProcessEvents | F5, B-2          |
| 18:28:43 → 18:40:55 | Three `Network` logon successes from 45.131.194.61. **Zero failures.**                       | DeviceLogonEvents   | F4, B-1          |
| 18:40:59       | Second `RemoteInteractive` session from 45.131.194.61. Per-user service registration repeats.     | DeviceLogonEvents   | F4, N1           |
| 18:41:13       | Second `cmd.exe` console opened.                                                                  | DeviceProcessEvents | F7               |
| 18:41 (×2)     | `cmd.exe /q /c del /q "...\OneDrive\Update\OneDriveSetup.exe"`, parented `userinit.exe` → `explorer.exe`. Machine housekeeping, not the operator. | DeviceFileEvents    | F6               |
| 18:41:16 / 18:41:40 | `net view` ×2.                                                                               | DeviceProcessEvents | F7, B-3          |
| 18:43:19       | `net view \\NH-FS-01`: shares on the named file server enumerated.                                | DeviceProcessEvents | F7, B-3          |
| 18:44:05       | `net user/domain` (malformed, no space). Operator typing error.                                   | DeviceProcessEvents | F7, B-3          |
| 18:44:31 / 18:44:39 | `net user`, then `net user /domain`.                                                         | DeviceProcessEvents | F7, B-3          |
| 18:45:34       | `net group /domain`: all domain groups enumerated.                                                | DeviceProcessEvents | F7, B-3          |
| 18:46:23       | `net group "NH-HR-Users" /domain`: HR group membership enumerated.                                | DeviceProcessEvents | F7, B-3          |
| 18:47:23       | `Interactive` and `CachedInteractive` (`::1`) entries. Session-local artefacts, not new logons.   | DeviceLogonEvents   | B-1              |
| 18:49:21       | `notepad \\NH-FS-01\IT\2026-05\SupportTickets\support_ticket_notes_20260528.txt`. In role.        | DeviceProcessEvents | F8               |
| 18:50:00       | `notepad \\NH-FS-01\IT\2026-05\WorkstationBuilds\workstation_build_notes_20260528.txt`. In role.  | DeviceProcessEvents | F8               |
| 18:50:56       | `notepad \\NH-FS-01\HR\2026-05\AccessRequests\access_request_queue_20260526.csv`. **Out of role.** | DeviceProcessEvents | F8, B-4          |
| 18:53          | `access_request_queue_20260526.csv` created in `C:\Users\m.reed\Documents\SupportReview`.         | DeviceFileEvents    | F9, B-5          |
| 18:54          | `employee_record_EMP-87291_20260527.txt` created in the same folder.                              | DeviceFileEvents    | F9, B-5          |
| 18:54          | `access_review_notes_20260528.txt` created in the same folder.                                    | DeviceFileEvents    | F9, B-5          |
| 18:55          | `support_review_202605.zip` created in `C:\Users\m.reed\Documents` by `powershell.exe`.           | DeviceFileEvents    | F9, B-5          |
| 18:56:12       | `net view \\tsclient`: redirected client drives checked.                                          | DeviceProcessEvents | F10, B-3         |
| 18:57          | `support_review_202605.zip` created at `\\tsclient\G\Temp\NimbusSupport` by `cmd.exe`. **Exfiltration.** | DeviceFileEvents | F10, B-5      |

Total hands-on-keyboard time: **31 minutes**, 18:26 to 18:57.

---

## 5. Findings

### F1, Target selection was performed entirely from public sources

**State it:** The attacker did not discover this environment by scanning it. The account, the machine, and the reason to connect the two were all published before any packet was sent.

**Show it:** Four artefacts, none from the SIEM, form a complete targeting chain.

| **Artefact**                  | **What it provided**                                                                                     |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Public professional profile   | Name (Mason Reed), employer (Nimbus Health), role (IT Support Technician), tenure (joined April 2026, "1 mo"), a public post announcing the new role, and a **personal email address** in a public contact field |
| Breach-exposure report        | That address present in three corpora, two containing plaintext passwords                                |
| Cached support reference      | `NH-WKS-IT-01`, public address `135.237.163.62`, internal `10.1.0.233`, and the instruction to use domain credentials. Cached 30 April 2026, two days after the technician's start date |
| Role matrix (MSP reference)   | `m.reed`, Standard User, start 2026-04-28, entitled to IT workstation, IT share, limited workstation support |

<img width="1448" height="1006" alt="01-f1-public-profile" src="https://github.com/user-attachments/assets/24aff379-a1f9-4d01-8136-7e6f61a27dcf" />

*Artefact 01. Role, employer, one-month tenure and a personal email address in a public contact field. Everything here was published voluntarily.*

**Interpret it:** Each artefact is individually harmless and was published deliberately. Together they answer every question an attacker needs answered: who to target, why that target is valuable, what password they might reuse, and which machine will accept it from the internet.

Three properties made this technician the optimal choice out of the estate's fifteen accounts. He was **IT**, so his credentials touch endpoints across departments rather than a single desk. He was **new**, one month in, so anomalous behaviour on his account would be indistinguishable from someone learning the job and he would have no baseline for what his own session history should look like. And his **personal** address was published, which is the pivot from "I know his name" to "I can look up his passwords". A corporate address would not have appeared in consumer breach corpora.

The cached support document is the finding with the clearest remediation. It converted a generic credential into a targeted one by naming the single internet-reachable host and confirming that domain credentials work there.

---

### F2, The credential came from a breach corpus, not from guessing

**State it:** The password was known before the first connection attempt. The failure pattern is inconsistent with brute force and consistent with testing a small set of held credentials.

**Show it:** The breach report returns three exposures. They are not equivalent.

| **Corpus**                                    | **Date**  | **Password data**                                              | **Usable today?**                            |
| --------------------------------------------- | --------- | -------------------------------------------------------------- | -------------------------------------------- |
| MySpace                                       | Jul 2008  | SHA1 of the **first ten characters only**, lowercased, unsalted | **No.** Truncated, case-flattened, 18 years stale |
| Combolists posted to Telegram                 | May 2024  | Plaintext email / username / password, partly infostealer-sourced | Yes                                        |
| Synthient credential-stuffing threat data     | Apr 2025  | Plaintext pairs aggregated specifically for reuse attacks       | Yes, and most recent                         |

Against that, the authentication evidence: **three** failures from 116.45.242.115 at 18:26:21–18:28:23, then success. The same host carries a background noise floor of thousands of failures from dozens of addresses against other usernames, none of which convert.

**Assessment:** The Synthient corpus is the probable source: it is the most recent, its contents are plaintext pairs, and its stated purpose is reuse against unrelated accounts, which is precisely the mechanism observed. The Telegram combolist cannot be excluded on the evidence available. **This attribution is an assessment, not a proof**; no telemetry can match a typed password to a corpus entry.

**Interpret it:** Four attempts is not a password attack. Attackers do not guess a working credential in four tries; they confirm one. The small number of failures most likely represents variants of a known password (case, appended digits, a year) rather than dictionary entries. Every one of these exposures predates the technician's April 2026 start date, so **nothing about Nimbus leaked**. A personal password was reused on a corporate account.

Note the corollary for containment: because the exposure originated outside the organisation, resetting the Nimbus password does not address the same credential's use on the technician's other accounts.

---

### F3, Initial access by RDP from external infrastructure

**State it:** The successful session was Remote Desktop from a routable public address, not someone at the desk.

**Show it:** Account-scoped filtering removes the noise floor before any manual triage is required.

**Query:**

```kusto
DeviceLogonEvents                              // law-cyber-range
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-wks-it-01"
| where AccountName == "m.reed"
| summarize
    Failures  = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess"),
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated)
  by RemoteIP, LogonType
| sort by Failures desc
```

**Result:**

*Scope: nh-wks-it-01 only, 25–31 May. Rows with no source address and zero successes are MDE shadow records and are excluded below.*

| RemoteIP        | LogonType         | Failures | Successes | First    | Last     | Assessment            |
| --------------- | ----------------- | -------- | --------- | -------- | -------- | --------------------- |
| 116.45.242.115  | Network           | 3        | 2         | 18:26:21 | 18:28:23 | Credential testing    |
| 116.45.242.115  | RemoteInteractive | 0        | 1         | 18:28:27 | 18:28:27 | Session established   |
| 45.131.194.61   | Network           | 0        | 3         | 18:28:43 | 18:40:55 | Second source         |
| 45.131.194.61   | RemoteInteractive | 0        | 1         | 18:40:59 | 18:40:59 | Second session        |
| (none)          | Batch             | 0        | 78        | 25 May   | 29 May   | `admin_maint.ps1` task |
| ::1             | CachedInteractive | 0        | 1         | 18:47:23 | 18:47:23 | Loopback, same session |

<img width="856" height="741" alt="02-f3-account-host-distribution" src="https://github.com/user-attachments/assets/b61519f8-4a5c-4b91-9149-1f68f20d9821" />

*Account-scoped sweep across the estate. Three LogonFailed events in total for m.reed on nh-wks-it-01. The nh-fs-01 and nh-dc-01 successes visible here are the two follow-up questions recorded in section 3.*

<img width="1350" height="996" alt="03-f3-source-address-profile" src="https://github.com/user-attachments/assets/78b243a4-1cd1-4f6a-9e9c-357b6114e48d" />

*Adding RemoteIP and LogonType separates the operator from the noise floor. 116.45.242.115 fails three times then succeeds; 45.131.194.61 succeeds with no failures at all.*

**Interpret it:** Only three failed logons exist for this account across six days. The "wall of failures" the hunt brief warns about is real but targets other usernames; binding the query to the account under review discards it without any judgement call. That is the generalisable technique: the noise floor is a property of the host, not of the account.

---

### F4, A second external source that never had to guess

**State it:** A second address used the same account twenty seconds after the first session opened, with zero failed logons.

**Show it:** 45.131.194.61 first appears at 18:28:43 with a `Network` success and opens its own `RemoteInteractive` session at 18:40:59. It records no failures at any point.

**Interpret it:** Two distinct infrastructure points, two distinct behaviours. The first address performed credential validation and paid the cost of three failures; the second arrived already holding a working password. This is consistent with either a single operator rotating egress, or credential handoff between a validation stage and a hands-on-keyboard stage, a common division of labour where access brokers and operators are separate parties. The evidence does not distinguish between them and this report does not claim to.

What it does foreclose is the insider explanation. A member of staff does not authenticate to his own workstation from two unrelated foreign addresses within thirteen minutes, and does not fail three times against his own password.

The ten-minute gap between the first orientation burst (ends 18:31:04) and the second shell (opens 18:41:13) is explained by this handover, not by idle time.

---

### F5, Orientation reconnaissance, correctly anchored

**State it:** The operator opened a console two minutes after the session established and ran a four-command orientation sequence. The intervening two minutes are Windows, not a person.

**Show it:** The session opens at 18:28:27. What follows immediately is first-logon provisioning: `userinit.exe`, `explorer.exe`, `sihost.exe`, `taskhostw.exe` (three instances), `ctfmon.exe`, `smartscreen.exe`, `dllhost.exe`, `TSTheme.exe`, `rdpclip.exe`, `SearchProtocolHost.exe`, `unregmp2.exe /FirstLogon`, `ie4uinit.exe -UserConfig`, `onedrivesetup.exe`, and Edge `setup.exe`. Every one is parented by a system process. No shell exists until 18:30:09.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where AccountName == "m.reed"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Result:** 228 rows. Parent-process distribution: `svchost.exe` 113, `msedge.exe` 42, `cmd.exe` 20, `explorer.exe` 16, `onedrivesetup.exe` 6, `winlogon.exe` 5, `net.exe` 5, `msedgewebview2.exe` 5, `setup.exe` 4, `powershell.exe` 2, others 10.

<img width="1382" height="1680" alt="04-f5-session-process-list" src="https://github.com/user-attachments/assets/be5e14a5-6f20-4895-ab63-39ccb03206a0" />

*First-logon provisioning fills the two minutes between session establishment and the first shell. The hourly admin_maint.ps1 task is visible above it, predating the intrusion.*

The twenty `cmd.exe` children are the entire operator contribution to a 228-row result set.

| **Time** | **Command**       | **Parent** | **Purpose**                          |
| -------- | ----------------- | ---------- | ------------------------------------ |
| 18:30:09 | (console opened)  | cmd.exe    | `conhost.exe 0xffffffff -ForceV1`    |
| 18:30:14 | `whoami`          | cmd.exe    | Identity                             |
| 18:30:20 | `hostname`        | cmd.exe    | Host                                 |
| 18:30:39 | `ipconfig /all`   | cmd.exe    | Network position, domain suffix      |
| 18:31:04 | `whoami /groups`  | cmd.exe    | Token group membership, entitlements |

**Interpret it:** The four commands answer, in order: who am I, where am I, what network am I on, and what can I reach. `whoami /groups` is the operationally significant one, because on a domain-joined host it returns the group memberships that determine share access, which is how the operator learned what was worth trying before trying it.

The anchoring point generalises. A logon timestamp is not an activity timestamp. Anchoring on 18:28:27 would place roughly two minutes of Windows provisioning inside the attacker's narrative and misrepresent the intrusion's start. Anchoring on the first shell-parented command is defensible in a way that anchoring on the session is not.

---

### F6, The deletion that looks like cleanup is machine housekeeping

**State it:** A file deletion inside the operator's session window is OneDrive removing its own installer, not the actor covering tracks.

**Show it:** At 18:41, seconds after the second console opened, `DeviceFileEvents` records:

```
cmd.exe /q /c del /q "C:\Users\m.reed\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
```

`InitiatingProcessFileName` is `cmd.exe`, which is what makes it a trap. Three properties resolve it:

1. **Lineage.** Parent chain is `userinit.exe` → `explorer.exe` → `cmd.exe`. That is a logon-shell autostart path, not a typed command.
2. **Duplication.** The identical entry appears **twice** at 18:41. Operators do not run the same deletion twice; startup entries fire per-session.
3. **Target and context.** It deletes OneDrive's own installer from OneDrive's own update directory, at the end of eleven minutes of continuous `onedrivesetup.exe` activity in the same profile (`/thfirstsetup`, then `/update /restart`). Nothing else was deleted.

<img width="1382" height="1680" alt="04-f5-session-process-list" src="https://github.com/user-attachments/assets/c229d2a5-c092-47e2-8527-24baa2164726" />

*Parent chain resolves the trap: userinit.exe to explorer.exe to cmd.exe, and the deletion appears twice. A logon-shell autostart path, not a typed command.*

The full deletion sweep over the window returns 33 rows: AppX package files under `C:\Program Files\Windows...` initiated by `svchost.exe -k wsappx`, a Defender definition patch, the OneDrive sequence, and nothing initiated by the operator's shells.

<img width="2735" height="1704" alt="06-f6-deletion-sweep" src="https://github.com/user-attachments/assets/0a285da4-5866-48c5-a7bb-6c3703b70e71" />

*All 33 deletions. AppX package files under svchost, a Defender definition patch, and the OneDrive sequence. Nothing initiated by the operator's shells.*

**Interpret it:** Both the operator's session and OneDrive's first-run cleanup are triggered by the same event, a brand-new profile being created on first logon, so they overlap in time by construction, not by coincidence of the attacker's choosing. `cmd.exe /q /c del /q` is the canonical installer self-clean idiom; a person types `del`.

Recorded as a finding rather than a footnote because the wrong reading here produces a false "anti-forensics" claim in the report, which would then have to be defended.

---

### F7, Enumeration well beyond the role

**State it:** The account listed the file server's shares, all domain users, all domain groups, and then the membership of the HR group specifically.

**Show it:** The second `cmd.exe` session, 18:41–18:46.

| **Time** | **Command**                          | **Yields**                                | **Role fit**       |
| -------- | ------------------------------------ | ----------------------------------------- | ------------------ |
| 18:41:16 | `net view`                           | Visible machines                          | Marginal           |
| 18:41:40 | `net view`                           | Repeat                                    | Marginal           |
| 18:43:19 | `net view \\NH-FS-01`                | Shares on the named file server           | Marginal           |
| 18:44:05 | `net user/domain` *(malformed)*      | Nothing; syntax error                     | n/a                |
| 18:44:31 | `net user`                           | Local accounts                            | Marginal           |
| 18:44:39 | `net user /domain`                   | All domain accounts                       | **Out of role**    |
| 18:45:34 | `net group /domain`                  | All domain groups                         | **Out of role**    |
| 18:46:23 | `net group "NH-HR-Users" /domain`    | HR group membership                       | **Out of role**    |

Each `net` command spawns a `net1.exe` child roughly simultaneously; the pairs are one command each, not two.

**Interpret it:** The malformed `net user/domain` at 18:44:05 is worth recording. It is a human typing error corrected 34 seconds later, which is corroborating evidence of interactive operation rather than scripted execution. A script does not fix its own syntax.

The trajectory is the finding. Two `net view` calls and a share listing are arguably within an endpoint-support role. `net group /domain` followed 49 seconds later by the HR group specifically is not: the operator enumerated everything, chose HR, and asked who was in it. An IT support technician has no workflow that requires HR group membership. The role matrix is the yardstick that makes this call available, and it is why the matrix belongs in the evidence bag rather than the appendix.

---

### F8, Out-of-role data access over SMB

**State it:** After two legitimate IT-share reads, the account opened an HR file over the network that its role does not entitle it to.

**Show it:**

| **Time** | **File opened**                                                                          | **Role fit**    |
| -------- | ------------------------------------------------------------------------------------------ | --------------- |
| 18:49:21 | `\\NH-FS-01\IT\2026-05\SupportTickets\support_ticket_notes_20260528.txt`                    | In role         |
| 18:50:00 | `\\NH-FS-01\IT\2026-05\WorkstationBuilds\workstation_build_notes_20260528.txt`              | In role         |
| 18:50:56 | `\\NH-FS-01\HR\2026-05\AccessRequests\access_request_queue_20260526.csv`                    | **Out of role** |

All three via `notepad`, parented by `cmd.exe`, which places the full UNC path on the command line and makes the process log a file-access record.

**Interpret it:** The two in-role reads immediately preceding the HR file are the reason behavioural detection alone would have struggled here. The sequence looks like continuous support work, and the account's own job involves reading support tickets and build notes. Only the role matrix separates the third open from the first two.

The 90-second spacing suggests the operator was reading, not sampling. The HR access-request queue is a high-value target for a reason beyond its contents: it documents who has requested access to what, which is reconnaissance material for a follow-on intrusion.

---

### F9, Local staging under a plausible folder name, then compression

**State it:** Three files were collected into a purpose-made folder named to resemble the account's own job, then compressed into a single archive.

**Query:**

```kusto
DeviceFileEvents                               // law-cyber-range
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where InitiatingProcessAccountName == "m.reed"
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath !contains "AppData" and FolderPath !contains "WindowsApps"
| project TimeGenerated, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Result:**

| **Time** | **File**                                    | **Folder**                                   | **Initiating** |
| -------- | ------------------------------------------- | -------------------------------------------- | -------------- |
| 18:28    | `Desktop.lnk`, `Downloads.lnk`              | `C:\Users\m.reed\Links`                      | explorer.exe (profile creation) |
| 18:53    | `access_request_queue_20260526.csv`         | `C:\Users\m.reed\Documents\SupportReview`    | cmd.exe        |
| 18:54    | `employee_record_EMP-87291_20260527.txt`    | `C:\Users\m.reed\Documents\SupportReview`    | cmd.exe        |
| 18:54    | `access_review_notes_20260528.txt`          | `C:\Users\m.reed\Documents\SupportReview`    | cmd.exe        |
| 18:55    | `support_review_202605.zip`                 | `C:\Users\m.reed\Documents`                  | powershell.exe |
| 18:57    | `support_review_202605.zip`                 | `\\tsclient\G\Temp\NimbusSupport`            | cmd.exe        |

Excluding `AppData` and `WindowsApps` reduces the result to six rows. Without those exclusions the same query returns hundreds of OneDrive and Edge provisioning events.

<img width="2735" height="1704" alt="06-f6-deletion-sweep" src="https://github.com/user-attachments/assets/98dee2a1-382d-4d11-80b7-32b0e51e7fa4" />

*The full chain in seven rows. Three files staged into SupportReview by cmd.exe, archived by powershell.exe, then the same archive written to \\tsclient\G\Temp\NimbusSupport at 18:57.*

**Interpret it:** Note the folder name and the archive name. `SupportReview` and `support_review_202605.zip` are chosen to survive a casual glance at an IT technician's Documents folder. It is the same masquerading instinct as the March incident's cross-share rename, applied to naming rather than location. Naming is the cheapest possible evasion and it works against human review, not against telemetry.

Two files in the archive were never opened in the session (`employee_record_EMP-87291_20260527.txt`, `access_review_notes_20260528.txt`); only the CSV appears in the Notepad sequence. They were copied, not read. That distinction matters for the notification assessment: the operator took material whose contents they may not have reviewed, so the exposure cannot be scoped by what the attacker is known to have seen.

The archive was built by `powershell.exe` while the staging copies were made by `cmd.exe`, and it lands one directory **above** the staging folder. The report should say "staged in `SupportReview`, archived to `Documents`" rather than collapsing both into one path.

---

### F10, Exfiltration through the RDP channel already in use

**State it:** The archive left the estate through the remote-desktop session's redirected client drive. No network upload occurred and none was needed.

**Show it:** At 18:56:12, `net view \\tsclient`. At 18:57, `support_review_202605.zip` created at `\\tsclient\G\Temp\NimbusSupport`, initiated by `cmd.exe`.

**Interpret it:** `\\tsclient\<drive>` is how a Windows host reaches drives shared back from the connecting RDP client. When the operator connected, their own machine's G: drive was mapped into the session. Writing to that path is, from the server's perspective, an ordinary file copy: the bytes travel inside the already-established, already-authenticated RDP connection on 3389.

The detection consequence is the point of this finding. There is no new outbound connection, no HTTP POST, no DNS lookup for a cloud endpoint, no anomalous destination. Proxy logs, CASB, egress firewall rules and web-upload DLP all see nothing, because the only outbound session is the RDP connection that the cached support document told the attacker to use. The evidence exists exclusively in file telemetry, and the only signature is a destination path beginning `\\tsclient\`.

`net view \\tsclient` 45 seconds before the copy is what elevates this from opportunistic to premeditated. The operator verified redirection was available before committing to the transfer. Had it not been, the session would have needed a different channel, and the check implies they knew that.

---

### F11, The file server was never touched interactively: a tested negative

**State it:** HR data was read from the file server, but nothing was ever executed on it. There was no second compromised host.

**Show it:** Two queries, both bound to nh-fs-01 across the full window.

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-fs-01"
| where AccountName == "m.reed" or InitiatingProcessAccountName == "m.reed"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Result: 0 rows.**

```kusto
DeviceLogonEvents                              // law-cyber-range
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-fs-01"
| where AccountName == "m.reed"
| summarize count() by LogonType, RemoteIP, ActionType
```

**Result:**

| LogonType | RemoteIP   | ActionType   | Count |
| --------- | ---------- | ------------ | ----- |
| Network   | 10.1.0.233 | LogonSuccess | 29    |
| Network   | (none)     | LogonSuccess | 10    |

<img width="2735" height="1704" alt="06-f6-deletion-sweep" src="https://github.com/user-attachments/assets/da56d09b-67be-4a4b-a210-5874a35f2b20" />

*Zero rows. The negative is the finding: nothing was ever executed on the file server.*

<img width="931" height="715" alt="09-f11-fs01-logon-types" src="https://github.com/user-attachments/assets/d6285635-6589-46c4-8d5f-9aa214c10339" />

*Network logons only, 29 of them sourced from 10.1.0.233, which is nh-wks-it-01. Share access, not a session.*

**Interpret it:** `Network` logon type is SMB share access, not an interactive session. 10.1.0.233 is nh-wks-it-01 per the environment sheet. Every HR file was reached over UNC paths from the workstation the operator was already sitting on; the file server served files, which is its function.

This matters for containment scope. The obvious assumption, that HR data was taken and therefore the file server was compromised, would have expanded the response to a second host, a second rebuild, and a second forensic capture, none of which the evidence supports. The absence of process events is only a finding because it was queried directly rather than inferred; the same discipline applied to the March incident's nh-wks-it-01 hop, which was likewise a logon with nothing behind it.

The ten blank-source logons are unattributed and are recorded as a gap.

---

## 6. Negative findings

| **Looked for**                                | **Where**                              | **Method applied**                                                                                          | **Conclusion**                                                                                                                                                     |
| --------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **N1** Persistence established by the operator | DeviceEvents, DeviceProcessEvents      | Swept `ServiceInstalled`, `ScheduledTask*`, `UserAccountCreated`, `UserAccountAddedToGroup`, `RegistryValueSet` across the full window | **None.** 38 `ServiceInstalled` events, all initiated by `svchost.exe` under the **machine account** `nh-wks-it-01$`, clustered at 18:28 and repeated at 18:40, one set per session. Every name is a Windows per-user service instance: `AarSvc`, `BcastDVRUserService`, `BluetoothUserService`, `CaptureService`, `cbdhsvc`, `CDPUserSvc`, `ConsentUxUserSvc`, `CredentialEnrollmentManager`, `DeviceAssociation`, `DevicesFlow`, `MessagingService`, `OneSyncSvc`, `PimIndexMaintenance`, `PrintWorkflow`, `UdkUserSvc`, `UnistoreSvc`, `UserDataSvc`, `WpnUserService`. No account creation, no group addition, no operator-initiated service or task. |
| **N2** Malware or dropped binaries            | DeviceProcessEvents                    | Reviewed every executed binary and its path across both sessions                                                 | **None.** Every binary was native and pre-existing: `whoami`, `hostname`, `ipconfig`, `net`, `net1`, `notepad`, `cmd`, `powershell`, `explorer`. Nothing was written to disk and executed. |
| **N3** Exploitation or privilege escalation   | DeviceProcessEvents, DeviceLogonEvents | Checked for anomalous parent-child chains, token manipulation, service abuse, escalation tooling                 | **None.** `m.reed` is a Standard User throughout. Every access came from valid credentials and existing share permissions. No elevation was attempted; none was needed. |
| **N4** A second compromised host              | DeviceProcessEvents, DeviceLogonEvents (nh-fs-01) | Direct query for process execution and logon type on the file server                                  | **None.** Zero process events; `Network` logons only, sourced from the workstation. See F11.                                                                        |
| **N5** Brute force as the access mechanism    | DeviceLogonEvents                      | Counted failures per source address against the account, compared to the estate noise floor                      | **Rejected.** Three failures then success from one address; a second address succeeded with zero. The high-volume failures on this host target other usernames and never convert. See F2, F3. |
| **N6** Network-based exfiltration             | DeviceFileEvents, DeviceProcessEvents  | Traced the archive from creation to final write                                                                  | **Correctly absent.** No upload tooling, no cloud client, no outbound transfer. The archive left over RDP drive redirection (F10). Note this is a *positive* finding of a different channel, not an unexplained absence. `DeviceNetworkEvents` was not independently swept; see gaps. |
| **N7** Patient or clinical data access        | n/a                                    | **Not tested.**                                                                                                  | **No conclusion available.** No query was run against `\\NH-FS-01\Clinical`. In a healthcare setting this must be closed before the incident is signed off. See Appendix D, D4. |

---

<img width="1189" height="1588" alt="10-n1-serviceinstalled-sweep" src="https://github.com/user-attachments/assets/6b34dd9c-6d11-4ae7-8549-e6bbe729394c" />

*N1. Every ServiceInstalled event is initiated by svchost.exe under the machine account nh-wks-it-01$, and the set repeats once per session. Windows per-user service registration, not operator persistence.*

---

## 7. MITRE ATT&CK mapping

| **Tactic**                   | **Technique**                                     | **ID**    | **Evidence ref**                                    |
| ---------------------------- | ------------------------------------------------- | --------- | --------------------------------------------------- |
| Reconnaissance               | Gather Victim Identity Information: Employee Names | T1589.003 | F1, public professional profile                     |
| Reconnaissance               | Gather Victim Identity Information: Email Addresses | T1589.002 | F1, personal address published in a public field   |
| Reconnaissance               | Gather Victim Identity Information: Credentials   | T1589.001 | F2, breach-corpus exposure                          |
| Reconnaissance               | Search Open Technical Databases / Open Websites   | T1596 / T1593 | F1, cached internal support reference           |
| Resource Development         | Compromise Accounts                               | T1586     | F2, credential obtained externally                  |
| Initial Access               | External Remote Services                          | T1133     | F3, RDP reachable from the internet                 |
| Initial Access / Persistence | Valid Accounts: Domain Accounts                   | T1078.002 | F2, F3, F4                                          |
| Credential Access            | Credential Stuffing                               | T1110.004 | F2, three failures then success on a held credential |
| Discovery                    | System Owner/User Discovery                       | T1033     | F5, `whoami`, `whoami /groups`                      |
| Discovery                    | System Information Discovery                      | T1082     | F5, `hostname`                                      |
| Discovery                    | System Network Configuration Discovery            | T1016     | F5, `ipconfig /all`                                 |
| Discovery                    | Network Share Discovery                           | T1135     | F7, `net view \\NH-FS-01`; F10, `net view \\tsclient` |
| Discovery                    | Account Discovery: Domain Account                 | T1087.002 | F7, `net user /domain`                              |
| Discovery                    | Permission Groups Discovery: Domain Groups        | T1069.002 | F7, `net group /domain`, `net group "NH-HR-Users" /domain` |
| Collection                   | Data from Network Shared Drive                    | T1039     | F8, HR share over SMB                               |
| Collection                   | Data Staged: Local Data Staging                   | T1074.001 | F9, `C:\Users\m.reed\Documents\SupportReview`       |
| Collection                   | Archive Collected Data: Archive via Utility       | T1560.001 | F9, `support_review_202605.zip`                     |
| Defense Evasion              | Masquerading: Match Legitimate Name or Location   | T1036.005 | F9, `SupportReview` / `support_review_202605.zip`   |
| Exfiltration                 | Exfiltration Over Alternative Protocol            | T1048     | F10, RDP drive redirection to `\\tsclient`          |

*T1048 is mapped as **confirmed** in this incident, unlike the March case where it was suspected. The distinction is an observed write to a client-side path.*

---

## 8. Recommendations

*Ranked by leverage. The two highest-leverage controls here are both configuration changes that cost nothing and would each have independently prevented the outcome.*

| **#** | **Recommendation**                                                                                                                                                                                              | **Addresses**                    | **Priority** | **Owner**             |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------------ | --------------------- |
| 1     | Require phishing-resistant MFA on all remote access. The intrusion required only a correct password. A second factor stops this at 18:28 regardless of how the credential was obtained, and no other control on this list is as decisive. | Valid-account access (F2, F3)    | Critical     | Identity / IT         |
| 2     | Remove direct RDP exposure to the internet on all `nh-*` hosts; place remote access behind a VPN or RD Gateway. The host is under continuous scanning from dozens of unrelated addresses. | External access surface (F1, F3) | Critical     | IT / Network          |
| 3     | Disable RDP drive and clipboard redirection by Group Policy where not operationally required (`Do not allow drive redirection`). This is the exfiltration channel, and it is the reason no egress control saw the theft. | Exfiltration channel (F10)       | Critical     | IT                    |
| 4     | Reset `m.reed` and revoke active sessions. Advise the employee that a personal credential is publicly exposed and must be changed everywhere it was reused, not only at Nimbus. | Compromised identity (F2)        | Critical     | Identity / SOC + HR   |
| 5     | Remove the cached remote-support reference from the public document cache and audit for other internal documents indexed publicly. The document named the target host, its public address, and the credential type to use. | Target selection (F1)            | High         | IT / Comms            |
| 6     | Review share permissions on `nh-fs-01` against the role matrix. An IT support technician's Standard User account could read `\\NH-FS-01\HR` unimpeded. Least privilege would have reduced this incident to enumeration with nothing to take. | Out-of-role access (F8)          | High         | IT / Data owners      |
| 7     | Onboard new hires with credential-exposure screening. This attack's entire premise was a reused personal password already sitting in a public corpus; a breach-exposure check at onboarding, plus enforced password uniqueness, closes the class. | Root cause (F2)                  | High         | IT / HR               |
| 8     | Implement the four detection rules in B2.7. Each corresponds to a step that generated telemetry and produced no alert-driven referral. Confirm current alert coverage first (Appendix D, D3). | Detection coverage               | Medium       | Detection engineering |
| 9     | Close the outstanding verification items in Appendix D before signing the incident off, in particular the domain controller logons (D5) and the clinical share (D4). | Investigation completeness       | Medium       | SOC                   |

---

# Part B, Tail

**Decision gate:** A compromise was confirmed and exfiltration was confirmed. B2 (Incident) is completed below. B1 (Threat Hunt) is marked "N/A, compromise confirmed"; its hypothesis is retained as the opening lead.

### B1, Threat Hunt tail

**Status:** N/A, compromise confirmed.

**Opening-lead hypothesis (falsifiable):** A newly hired IT support account whose credentials are publicly exposed has been used by someone other than its owner, and the activity extends beyond the account's role. **PROVED** (see B2).

**Counter-hypothesis tested and rejected:** A curious new starter exploring the environment beyond his remit. Rejected on four independent grounds: two unrelated foreign public source addresses (F3, F4); three failed authentications against his own password before the first success (F2, F3); deliberate staging under a masquerading folder name followed by compression (F9); and transfer of the archive to a drive belonging to the connecting client machine, which is not the employee's Nimbus workstation (F10).

### B2, Incident tail

*Framing per NIST SP 800-61r3 (CSF 2.0 Functions); containment/eradication/recovery per SANS PICERL.*

### B2.1 Impact and dwell time

| **Field**                      | **Value**                                                                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| First malicious activity       | 28 May 2026 18:26:21 (first credential test from 116.45.242.115)                                                                           |
| Session established            | 28 May 2026 18:28:27                                                                                                                       |
| First detection                | **[unverified]** No alert observed. `SecurityAlert` / `SecurityIncident` were not queried; absence is inferred from the lack of an alert-driven referral. See Appendix D, D3. |
| Dwell time to detection        | No detection established. 31 minutes of hands-on-keyboard activity, uninterrupted.                                                          |
| Time to containment            | Not contained at time of writing; see B2.3                                                                                                  |
| Hosts confirmed compromised    | nh-wks-it-01 only (F11)                                                                                                                     |
| Accounts confirmed compromised | `m.reed` (Standard User). No privileged account implicated.                                                                                 |
| Data confirmed accessed        | `access_request_queue_20260526.csv` (HR); `support_ticket_notes_20260528.txt`, `workstation_build_notes_20260528.txt` (IT, in role)          |
| Data confirmed staged          | `access_request_queue_20260526.csv`, `employee_record_EMP-87291_20260527.txt`, `access_review_notes_20260528.txt` in `C:\Users\m.reed\Documents\SupportReview`; archived as `support_review_202605.zip` |
| **Data confirmed exfiltrated** | **`support_review_202605.zip`, written to `\\tsclient\G\Temp\NimbusSupport` at 18:57. Contents: the three files above.**                     |
| Integrity impact               | None observed. No file was modified or deleted by the operator.                                                                             |
| Persistence                    | None established (N1)                                                                                                                       |
| Business impact                | Confirmed theft of HR personal data including at least one individually identified employee record; notification obligation triggered pending data-element review |

*Accessed, staged and exfiltrated are kept separate. Unlike the March incident, this one reaches the third category on direct evidence: a file-creation event at a client-side path.*

### B2.2 Root cause

Three ordinary conditions met, and none of them was a security failure of the kind that requires a sophisticated adversary to exploit.

**A personal password was reused on a corporate account.** The credential was exposed in a public breach corpus before the employee joined Nimbus. Nothing about the clinic leaked. This is the proximate cause, and it is also the least controllable of the three from Nimbus's side, which is precisely why the other two matter.

**Remote Desktop was reachable from the open internet and accepted a password alone.** The host is under continuous scanning from unrelated parties; any working credential would have opened it. Multi-factor authentication would have made the exposed password worthless.

**The organisation published its own target list.** A public professional profile supplied the identity and the personal email address. A cached internal support document supplied the hostname, the public IP, and the confirmation that domain credentials work there. The attacker performed no scanning and no research beyond reading what was already indexed.

Underneath these sits the growth pressure the environment note describes. Nimbus hired across every department at once and put new starters on existing shared workstations: growth first, access review later. That is why a one-month IT hire had a Standard User account that could read the HR share unimpeded, and why a support document written to help new staff find the remote-access endpoint was treated as low-sensitivity enough to end up in a public cache.

No exploitation, no malware, no privilege escalation, and no persistence were required at any stage.

### B2.3 Containment, eradication, recovery

*For each action: the naive move it rejects, then the correct one.*

| **Phase** | **Action (correct)**                                                                                                        | **Naive move it rejects**                                                                                                                                        | **Owner / verify**                     |
| --------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Contain   | Isolate nh-wks-it-01 and remove RDP exposure at the perimeter **before or alongside** the credential reset.                   | Reset the password and call it done. A reset does not terminate live RDP sessions, does not close the internet-facing surface, and does not undo an archive that has already left. | IT / Network, verify externally        |
| Contain   | Reset `m.reed`, revoke all active sessions explicitly, and confirm no session survives the reset.                             | Assume the reset evicts the operator. Established RDP sessions persist through a password change.                                                                | Identity, confirm zero active sessions |
| Contain   | Disable drive redirection by GPO now, not as a later hardening item.                                                          | Treat redirection as a hardening backlog item. It is the live exfiltration channel and costs nothing to close.                                                   | IT, verify by policy result            |
| Contain   | Treat 116.45.242.115 and 45.131.194.61 as detection IOCs; block only as a short-term measure.                                 | Block both addresses and consider it contained. Addresses rotate trivially; the exposure is the problem, and a second address in this very incident proves the point. | SOC                                    |
| Eradicate | Recover and hash `support_review_202605.zip` and the three files in `SupportReview` **before** deletion, and inspect contents. | Delete the staged folder immediately. Those files define the notification scope and are the primary evidence of what was taken.                                  | IR, chain of custody per B2.5          |
| Eradicate | Delete `C:\Users\m.reed\Documents\SupportReview`, the archive, and the stale profile after capture.                            | Remove the files only. The profile is an intrusion artefact and its `Recent` folder carries attribution evidence.                                                | IT, after evidence capture             |
| Eradicate | Advise the employee to change the exposed password wherever it was reused personally, and enrol the address in breach monitoring. | Treat this as a Nimbus-only credential problem. The exposure originated outside the organisation and persists outside it.                                        | HR + IT, handled supportively          |
| Eradicate | Request removal of the cached support document and audit for other internal material in public caches.                        | Remove the live page. The live page was already gone; the cached snapshot is what the attacker read.                                                             | IT / Comms, verify by search           |
| Recover   | Reduce `nh-fs-01` share permissions against the role matrix before restoring the account.                                     | Restore the account with permissions unchanged. A repeat incident would have identical scope.                                                                     | IT / Data owners                       |
| Recover   | Close Appendix D items D4 (clinical share) and D5 (domain controller logons) before declaring closure.                        | Close on the workstation evidence alone. Two lines of inquiry remain unworked.                                                                                    | SOC                                    |

**A note on the employee.** Mason Reed is a victim in this incident, not a suspect. His only contribution was reusing a personal password, at a point before he joined the organisation, on an account whose exposure Nimbus never screened for. Any communication should be framed accordingly.

### B2.4 Indicators of compromise (ordered by Pyramid of Pain)

| **Type**             | **Indicator**                                                                                 | **Context**                                          | **Confidence** |
| -------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------- |
| TTP (hardest)        | File write to a `\\tsclient\` path following archive creation                                   | RDP drive-redirection exfiltration (F10)             | High           |
| TTP                  | `net view \\tsclient` executed by a user account                                                | Redirection reconnaissance before transfer (F10)     | High           |
| TTP                  | One external address authenticating to an account with a handful of failures then success, against a host with a high unrelated failure volume | Credential reuse distinguished from spray (F2, F3) | High           |
| TTP                  | Two external addresses using one account within minutes, one with zero prior failures           | Validation/operator handoff (F4)                     | High           |
| TTP                  | `whoami` → `hostname` → `ipconfig /all` → `whoami /groups` under `cmd.exe` within 60 seconds     | Orientation burst (F5)                               | High           |
| TTP                  | `net group /domain` followed within a minute by a named departmental group                      | Targeted group enumeration (F7)                      | High           |
| Artefact             | Staging folder and archive named to match the compromised account's own job function            | Masquerading by naming (F9)                          | Medium         |
| File                 | `support_review_202605.zip`                                                                     | Exfiltrated archive                                  | High           |
| File                 | `C:\Users\m.reed\Documents\SupportReview\` (three files)                                        | Staged content                                       | High           |
| Account              | `m.reed` authenticating with `LogonType == RemoteInteractive` from a public address             | Compromised identity                                 | High           |
| Host / IP (cheapest) | 116.45.242.115, 45.131.194.61                                                                   | Operator exit addresses; monitor, do not treat as containment | Medium |

*The top three rows are the ones worth building detections on. The addresses are the cheapest thing in this incident for the adversary to replace, and they replaced one mid-session.*

### B2.5 Chain of custody

| **Evidence item**                                        | **Collected** | **By**    | **Hash**                   | **Storage**                           |
| ---------------------------------------------------------- | ------------- | --------- | -------------------------- | ------------------------------------- |
| `support_review_202605.zip` (`C:\Users\m.reed\Documents`)  | [pending]     | [ANALYST] | [to compute on collection] | Case evidence store, NH-INC-2026-0528 |
| `SupportReview\` three staged files                        | [pending]     | [ANALYST] | [to compute, each]         | Restricted, PII; access-logged        |
| `m.reed` profile on nh-wks-it-01 (incl. `Recent`)          | [pending]     | [ANALYST] | [to compute]               | Case evidence store                   |
| OSINT artefacts 01–04 (profile, breach report, cached page, role matrix) | 2026-08-15 | [ANALYST] | [to compute] | Case evidence store                   |
| KQL query exports (all findings)                           | 2026-08-15    | [ANALYST] | [to compute]               | Case evidence store                   |
| Screenshot exhibits (F1–F11)                               | 2026-08-15    | [ANALYST] | [to compute]               | Case evidence store                   |

*The exfiltrated copy at `\\tsclient\G\Temp\NimbusSupport` is on attacker-controlled hardware and is not recoverable.*

### B2.6 Regulatory notification

| **Field**              | **Value**                                                                                                                                                              |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Personal data involved | **Yes, and confirmed exfiltrated.** An individually identified employee record (`employee_record_EMP-87291_20260527.txt`), an HR access-request queue, and access-review notes. |
| Data elements          | **Not yet inspected.** Determines which regime applies and whether notification is mandatory. This is the single blocking item.                                        |
| Regulation(s) engaged  | US state breach-notification law (employment records) is engaged on current evidence. **GDPR** applies with a 72-hour authority-notification window if any data subject is in scope. **HIPAA** applies with a 60-day window **if** occupational-health or clinical content sits inside the employee record. That is plausible given the clinic's new occupational-health workflow, and it must be checked rather than assumed. |
| Notification required  | **Assessment is mandatory, not discretionary.** Unlike the March incident, exfiltration is confirmed rather than inferred, so this cannot be closed as unproven access. |
| Clock start            | Runs from discovery. The exfiltration event itself is 28 May 2026 18:57 (local) / 29 May 01:57 UTC.                                                                    |
| Notified               | [pending Legal/Privacy action]                                                                                                                                          |

*Two subjects warrant specific mention: the individual identified in `employee_record_EMP-87291`, and every individual named in the access-request queue, who are data subjects by virtue of an access request they made and would not expect to be exposed by.*

*This must not be handled as an internal IT matter. "We reset his password" is not a defensible response to confirmed exfiltration of employee personal data.*

### B2.7 Detection engineering

Each rule corresponds to a step in this incident that generated telemetry and produced no alert-driven referral. All four would have fired on 28 May.

**D1. Exfiltration to a redirected RDP client drive**

*The highest-value rule in this report, because no network control sees this event. Fires at 18:57.*

```kusto
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath startswith @"\\tsclient\"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, InitiatingProcessFileName
```

*Tune by excluding any support workflow that legitimately uses redirection. In this estate, none does.*

**D2. External RDP success**

*Fires at 18:28:27, before any data is touched. The same rule was the top recommendation in the March report and remains uneffected.*

```kusto
DeviceLogonEvents
| where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project TimeGenerated, DeviceName, AccountName, RemoteIP
```

**D3. Low-volume credential validation followed by success**

*Distinguishes reuse from spray by keying on the ratio, not the count. Fires at 18:28:23.*

```kusto
DeviceLogonEvents
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| summarize
    Failures  = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess"),
    Accounts  = dcount(AccountName)
  by RemoteIP, bin(TimeGenerated, 1h)
| where Successes > 0 and Failures between (1 .. 20) and Accounts <= 2
```

*The `Accounts <= 2` clause is what excludes the estate's background spray, which touches dozens of usernames from each source.*

**D4. Departmental group enumeration by an out-of-department account**

*Fires at 18:46:23. Requires the role matrix as a lookup to be precise; the coarse version below alerts on any user-account execution.*

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe")
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "group" and ProcessCommandLine has "/domain"
| where AccountName !endswith "$"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

---

**Appendices**

## Appendix A, Full queries

All queries are bound to 25–31 May 2026 and, except where noted, scoped to `nh-wks-it-01`. The workspace is shared and holds a separate March 2026 incident on the same estate, so the time bind and host scope are load-bearing.

**A note that cost two queries:** `DeviceName == "nh-wks-it-01"` returns nothing. MDE stores the FQDN. Use `has`.

### Scoping and account identification

**Field-value discovery (run this first)**

*Establishes the literal strings in the data before any filter is written. Would have prevented both empty-result incidents in this investigation.*

```kusto
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| summarize count() by DeviceName, AccountName, ActionType
| sort by count_ desc
```

**Source-address profile for the account under review (F3, F4)**

*The single query that separates the operator from the noise floor.*

```kusto
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-wks-it-01"
| where AccountName == "m.reed"
| summarize
    Failures  = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess"),
    FirstSeen = min(TimeGenerated),
    LastSeen  = max(TimeGenerated)
  by RemoteIP, LogonType
| sort by Failures desc
```

**Activity-hour location**

*Used to locate the session when local-time display made the window filter unreliable.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-wks-it-01"
| summarize count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

### Execution and discovery

**Full session process review (F5, F6, F7)**

*No keyword list. 228 rows, of which 20 are the operator. Parent-process distribution does the triage.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where AccountName == "m.reed"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Parent-process lineage test (F6)**

*Resolves whether a `cmd.exe`-initiated deletion is a person or an installer.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where ProcessCommandLine has "OneDriveSetup.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessParentFileName
| sort by TimeGenerated asc
```

### Collection and exfiltration

**Staging and archive chain (F9, F10)**

*Excluding `AppData` and `WindowsApps` reduces hundreds of provisioning events to six meaningful rows.*

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where InitiatingProcessAccountName == "m.reed"
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath !contains "AppData" and FolderPath !contains "WindowsApps"
| project TimeGenerated, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Redirected-drive confirmation (F10)**

*`FolderPath` carries the directory only; the filename is in `FileName`. Expand the row rather than reading the grid cell.*

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where FolderPath has "tsclient"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```

**Deletion sweep (F6)**

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-05-28) .. datetime(2026-05-30))
| where DeviceName has "nh-wks-it-01"
| where ActionType == "FileDeleted"
| project TimeGenerated, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

### Negative tests

**Persistence sweep (N1)**

```kusto
DeviceEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-wks-it-01"
| where ActionType has_any ("ScheduledTask", "ServiceInstalled", "UserAccountCreated",
        "UserAccountAddedToGroup", "RegistryValueSet")
| project TimeGenerated, ActionType, AdditionalFields,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

**Persistence sweep, process side (N1). Did not execute, see Appendix D, D2**

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-wks-it-01"
| where ProcessCommandLine has_any ("schtasks", "sc create", "sc.exe", "reg add",
        "New-Service", "net user", "net localgroup", "RunOnce")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessAccountName
| sort by TimeGenerated asc
```

**File-server execution test (F11, N4)**

*Zero rows. The negative is the finding.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-fs-01"
| where AccountName == "m.reed" or InitiatingProcessAccountName == "m.reed"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**File-server logon characterisation (F11, N4)**

```kusto
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-05-25) .. datetime(2026-05-31))
| where DeviceName has "nh-fs-01"
| where AccountName == "m.reed"
| summarize count() by LogonType, RemoteIP, ActionType
```

---

## Appendix B, Raw evidence extracts

### B-1 Logon profile on nh-wks-it-01 (F3, F4)

*DeviceLogonEvents, m.reed, 25–31 May. Rows with a blank source and zero successes are MDE `Unknown`-type shadow records paired with an adjacent real event; they are not separate logons.*

| **RemoteIP**     | **LogonType**     | **Failures** | **Successes** | **First**    | **Last**     |
| ---------------- | ----------------- | ------------ | ------------- | ------------ | ------------ |
| 116.45.242.115   | Network           | 3            | 2             | 18:26:21     | 18:28:23     |
| 116.45.242.115   | RemoteInteractive | 0            | 1             | 18:28:27     | 18:28:27     |
| 45.131.194.61    | Network           | 0            | 3             | 18:28:43     | 18:40:55     |
| 45.131.194.61    | RemoteInteractive | 0            | 1             | 18:40:59     | 18:40:59     |
| (none)           | Batch             | 0            | 78            | 25 May 04:16 | 29 May 01:25 |
| (none)           | Interactive       | 0            | 1             | 18:47:23     | 18:47:23     |
| ::1              | CachedInteractive | 0            | 1             | 18:47:23     | 18:47:23     |

Account-level totals across the window: 89 `LogonSuccess`, 55 `LogonAttempted`, **3** `LogonFailed`.

*`LogonAttempted` is an MDE record that does not resolve to success or failure. Do not count it as failures.*

### B-2 Orientation burst (F5)

*DeviceProcessEvents, all children of `cmd.exe`. Session established 18:28:27; console opened 18:30:09.*

| **Time** | **ProcessCommandLine** | **Parent** |
| -------- | ---------------------- | ---------- |
| 18:30:09 | `conhost.exe 0xffffffff -ForceV1` | cmd.exe |
| 18:30:14 | `whoami`               | cmd.exe    |
| 18:30:20 | `hostname`             | cmd.exe    |
| 18:30:39 | `ipconfig  /all`       | cmd.exe    |
| 18:31:04 | `whoami  /groups`      | cmd.exe    |

*MDE renders a double space between the command and its switch. Reproduced as logged.*

### B-3 Enumeration and channel check (F7, F10)

*DeviceProcessEvents, second `cmd.exe` session. `net.exe` hands off to `net1.exe` within milliseconds; the pairs are one command each.*

| **Time** | **ProcessCommandLine**              | **Parent** |
| -------- | ----------------------------------- | ---------- |
| 18:41:13 | `conhost.exe 0xffffffff -ForceV1`   | cmd.exe    |
| 18:41:16 | `net  view`                         | cmd.exe    |
| 18:41:40 | `net  view`                         | cmd.exe    |
| 18:43:19 | `net  view \\NH-FS-01`              | cmd.exe    |
| 18:44:05 | `net  user/domain`                  | cmd.exe    |
| 18:44:05 | `net1  user/domain`                 | net.exe    |
| 18:44:31 | `net  user`                         | cmd.exe    |
| 18:44:39 | `net  user /domain`                 | cmd.exe    |
| 18:45:34 | `net  group /domain`                | cmd.exe    |
| 18:46:23 | `net  group "NH-HR-Users" /domain`  | cmd.exe    |
| 18:56:12 | `net  view \\tsclient`              | cmd.exe    |

### B-4 Documents opened (F8)

*DeviceProcessEvents. Notepad carries the full UNC path on the command line.*

| **Time** | **Share** | **Path**                                                            | **Role fit**    |
| -------- | --------- | -------------------------------------------------------------------- | --------------- |
| 18:49:21 | IT        | `\2026-05\SupportTickets\support_ticket_notes_20260528.txt`           | In role         |
| 18:50:00 | IT        | `\2026-05\WorkstationBuilds\workstation_build_notes_20260528.txt`     | In role         |
| 18:50:56 | **HR**    | `\2026-05\AccessRequests\access_request_queue_20260526.csv`           | **Out of role** |

### B-5 Staging, archiving, exfiltration (F9, F10)

*DeviceFileEvents, `AppData` and `WindowsApps` excluded.*

| **Time** | **ActionType** | **FolderPath**                              | **FileName**                             | **Initiating** |
| -------- | -------------- | -------------------------------------------- | ---------------------------------------- | -------------- |
| 18:28    | FileCreated    | `C:\Users\m.reed\Links`                     | `Desktop.lnk`                            | explorer.exe   |
| 18:28    | FileCreated    | `C:\Users\m.reed\Links`                     | `Downloads.lnk`                          | explorer.exe   |
| 18:53    | FileCreated    | `C:\Users\m.reed\Documents\SupportReview`   | `access_request_queue_20260526.csv`      | cmd.exe        |
| 18:54    | FileCreated    | `C:\Users\m.reed\Documents\SupportReview`   | `employee_record_EMP-87291_20260527.txt` | cmd.exe        |
| 18:54    | FileCreated    | `C:\Users\m.reed\Documents\SupportReview`   | `access_review_notes_20260528.txt`       | cmd.exe        |
| 18:55    | FileCreated    | `C:\Users\m.reed\Documents`                 | `support_review_202605.zip`              | powershell.exe |
| 18:57    | FileCreated    | `\\tsclient\G\Temp\NimbusSupport`           | `support_review_202605.zip`              | cmd.exe        |

*The first two rows are profile provisioning and are retained to show the contrast: system-initiated, at session start, in `Links`.*

### B-6 Estate noise signatures ruled out

*Recorded so future hunts in this estate can discard them immediately.*

| **Signature**                                                                       | **Source**                          | **Cadence**                        |
| ------------------------------------------------------------------------------------- | ----------------------------------- | ---------------------------------- |
| `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\admin_maint.ps1"` under `svchost.exe` | Pre-existing scheduled maintenance task | Hourly from 27 May; 78 Batch logons |
| `"CollectGuestLogs.exe"` under `waappagent.exe`                                       | Azure VM guest agent                | Roughly hourly, continuous         |
| `upload "C:\ProgramData\..."` under `mssense.exe`                                     | Defender sensor telemetry upload    | Periodic                           |
| `cmd.exe /q /c del /q "...\OneDrive\Update\OneDriveSetup.exe"` (parent `explorer.exe`) | OneDrive self-maintenance           | Per new profile, duplicated        |
| 19 × `ServiceInstalled` under machine account `nh-wks-it-01$`                          | Windows per-user service registration | Once per interactive session      |
| `LogonAttempted` and `LogonType == Unknown` paired with an adjacent success            | MDE shadow record                   | Every logon; do not double-count   |

*The `-ExecutionPolicy Bypass` PowerShell task is the most alarming-looking entry in this estate and is entirely benign. Its parentage (`svchost.exe`), its cadence (hourly on the minute), and its start date (before the intrusion) all establish it. It continues unchanged after the operator leaves.*

---

## Appendix C, Reference list

- MITRE ATT&CK, <https://attack.mitre.org/>
- Microsoft Defender for Endpoint advanced hunting schema reference, <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables>
- Microsoft, Remote Desktop Services device and resource redirection policy settings, <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/>
- NIST SP 800-61r3, Incident Response Recommendations and Considerations, <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- SANS PICERL incident-handling process, <https://www.sans.org/>
- RFC 1918, Address Allocation for Private Internets, <https://datatracker.ietf.org/doc/html/rfc1918>
- Windows logon type reference (event 4624), <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor>

### Placeholder legend

*The identities, hosts and addresses in this report are those of a training environment and are reproduced as recorded.*

| **Placeholder** | **Refers to**                                                        |
| --------------- | -------------------------------------------------------------------- |
| [ANALYST]       | Reporting analyst, SOC / Cyber Range Operations                      |
| m.reed          | IT Support Technician, Standard User; compromised account and victim |
| l.rodriguez     | IT Administrator; the estate's only Administrator-level user account |
| NH-Admin        | Built-in domain administrator account; not implicated in this incident |
| `nh-*`          | Nimbus Health estate hosts                                           |
| 10.1.0.x        | Internal addresses                                                   |

---

## Appendix D, Outstanding verification

*Items whose value or claim could not be closed against a retained query result. Each is referenced at its point of use. None reverses a conclusion; all change how defensible the report is under challenge.*

| **#** | **Item**                                                       | **Status**                                                                                          | **What closes it**                                                                                                    |
| ----- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| D1    | Portal timezone offset (§1, timeline)                            | Observed as UTC-7 by inference: rows displayed at 27 May 23:29 satisfied a filter with a 28 May lower bound | Confirm the workspace/browser timezone setting, or re-run one query with `| extend UTC = format_datetime(TimeGenerated,'yyyy-MM-dd HH:mm:ss')` |
| D2    | Process-side persistence sweep (N1)                              | Query failed on a syntax error (concatenated statements) and was not re-run. Conclusion rests on `DeviceEvents` alone | Re-run the `schtasks` / `reg add` / `New-Service` command-line sweep in Appendix A                                    |
| D3    | "No alert fired" (B2.1, §8 rec 8, B2.7)                          | Inferred from the absence of an alert-driven referral; `SecurityAlert` never queried                     | `SecurityAlert` over 25–31 May filtered to `m.reed` and the three hosts                                               |
| D4    | Clinical / patient data access (N7)                              | **Not tested.** No query run against `\\NH-FS-01\Clinical`                                               | `DeviceFileEvents` and `DeviceProcessEvents` filtered on `Clinical` across the window, all accounts                   |
| D5    | 26 `LogonSuccess` for m.reed on nh-dc-01 (§3 gaps)               | Observed in the initial sweep, never characterised. **Largest open gap.**                                | Summarize by `LogonType`, `RemoteIP`, `ActionType` on nh-dc-01 as done for nh-fs-01                                   |
| D6    | 10 blank-source `Network` logons on nh-fs-01 (F11)               | Unattributed                                                                                             | Correlate by timestamp against nh-wks-it-01 session activity, or fall back to `RemoteDeviceName`                      |
| D7    | Breach corpus attribution (F2)                                   | Assessed, not proven. Two of three exposures contain plaintext credentials                               | Not a query. Cannot be closed from telemetry; state as an assessment in any external communication                    |
| D8    | Data elements inside the three exfiltrated files (B2.6)          | Not inspected. **Blocks the notification determination.**                                                | Not a query. Inspection of the recovered files under Legal/Privacy supervision                                        |
| D9    | Sub-second timestamps for the staging and archive events (F9, B-5) | Grid cells truncated at the minute; not expanded per row                                                | Re-run the staging query and expand each row, or project `format_datetime(TimeGenerated,'HH:mm:ss.fff')`              |
| D10   | Whether the same credential was used elsewhere in the estate (B2.3) | Not tested; scope was bound to one host by design                                                     | Estate-wide `DeviceLogonEvents` for `m.reed` with `not(ipv4_is_private(RemoteIP))` across a wider window              |

*Note on identifiers: `NH-INC-2026-0528` is an analyst-assigned case reference for this report. It is not a Sentinel `IncidentNumber` and not an MDE portal incident ID. No query in this report cites it, and none should.*
