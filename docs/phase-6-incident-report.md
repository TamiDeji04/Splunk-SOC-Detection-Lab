# Phase 6: Incident Report

**Report ID:** SOC-LAB-2026-001  
**Date:** June 29, 2026  
**Analyst:** Tamilo Eadedeji  
**Affected host:** `WIN-K1DGK4BA0UM` (Windows 11 ARM VM, UTM)  
**SIEM:** Splunk Enterprise 10.4.0 (macOS host, `index=endpoint`)  
**Severity:** High (simulated)  
**Status:** Contained — lab exercise, not a production incident

---

## Executive summary

On June 29, 2026, Splunk alerts fired on a lab Windows endpoint following a deliberate attack simulation. A burst of failed logons (T1110.001) was followed by encoded PowerShell execution (T1059.001), outbound HTTP beaconing from PowerShell (T1071.001), and a registry Run key persistence entry (T1547.001). All four corresponding alerts appeared in Splunk's Triggered Alerts queue between 20:11 and 20:15 CDT. Investigation confirmed the activity was confined to the disposable VM; no lateral movement was observed. Recommended containment actions for a production scenario are documented below.

---

## Timeline

| Time (CDT) | Event | MITRE | Source |
|---|---|---|---|
| ~20:10 | Brute force simulation — 12 failed logons against `baduser` | T1110.001 | Security Event 4625 |
| 20:11:50 | Alert fired: Encoded PowerShell Execution | T1059.001 | Triggered Alerts |
| 20:12:25 | Alert fired: Suspicious Outbound | T1071.001 | Triggered Alerts |
| 20:13:06 | Alert fired: Registry Run Key | T1547.001 | Triggered Alerts |
| ~20:13 | Encoded PowerShell executed (`-EncodedCommand`) | T1059.001 | Sysmon Event 1 |
| ~20:13 | Outbound HTTP beacon to example.com | T1071.001 | Sysmon Event 3 |
| ~20:13 | Run key `AtomicRedTeamPersistence` created | T1547.001 | Sysmon Event 13 |
| 20:15:00 | Alert fired: Brute Force Password Guessing | T1110.001 | Triggered Alerts (scheduled) |

See [Phase 5 triggered alerts screenshot](screenshots/phase-5-triggered-alerts-all-fired.png).

---

## Detection

| Alert | Fired | What it indicated |
|---|---|---|
| **Alert - T1059.001 - Encoded PowerShell Execution** | 20:11:50 CDT | PowerShell launched with `-EncodedCommand` — common obfuscation technique |
| **Detect - T1071.001 - Suspicious Outbound** | 20:12:25 CDT | PowerShell initiated outbound network connections |
| **Detect - T1547.001 - Registry Run Key** | 20:13:06 CDT | New value under a Windows Run key — persistence |
| **Detect - T1110.001 - Brute Force Password Guessing** | 20:15:00 CDT | More than five failed logons from one source within five minutes |

The real-time alerts appeared within seconds of the simulated activity. The brute force alert arrived last because it runs on a five-minute scheduled cron, not because the detection logic failed.

---

## Analysis

After the alerts fired, I ran the following searches to confirm scope and build context for each stage of the chain.

### 1. Brute force scope

```spl
index=endpoint EventCode=4625 earliest=-1h
| stats count by Account_Name, Source_Network_Address
| sort -count
```

**Finding:** Failed logons clustered on account **`baduser`** with **24** events from source **`::1`** (IPv6 loopback). Account **`analyst`** also appeared in stats from earlier testing. No evidence of attempts against multiple remote IPs — activity consistent with a local simulation, not a distributed brute force campaign.

![Brute force detection results](screenshots/phase-5-detect-brute-force-results.png)

---

### 2. Successful logon after failures (lateral check)

```spl
index=endpoint EventCode=4624 earliest=-1h
| table _time, Account_Name, Logon_Type, Source_Network_Address
| sort _time
```

**Finding:** [Review interactive logons (Logon Type 2) in the same window as the 4625 burst. In this lab the attacker did not need a separate successful logon — the encoded PowerShell ran under the existing `analyst` session. In a production scenario, a 4624 immediately after a 4625 spike would be a priority pivot.]

---

### 3. Encoded PowerShell execution

```spl
index=endpoint EventCode=1 CommandLine="*EncodedCommand*" earliest=-1h
| table _time, User, Image, CommandLine, ParentImage
```

**Finding:** Two process-creation events on `WIN-K1DGK4BA0UM`. User **`WIN-K1DGK4BA0UM\analyst`**. Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Command line contained **`-NoProfile -EncodedCommand`** with a Base64 payload. Parent process in at least one event was **`splunkd.exe`** (forwarder context during testing).

![Encoded PowerShell events](screenshots/phase-5-detect-encoded-powershell-results.png)

---

### 4. Outbound connections (C2-style beacon)

```spl
index=endpoint EventCode=3 (Image="*powershell.exe" OR Image="*cmd.exe") earliest=-1h
| table _time, Image, DestinationIp, DestinationPort, DestinationHostname
| sort _time
```

**Finding:** PowerShell connected to external addresses including **`104.28.23.154:80`**, **`172.66.147.243:80`**, and **`23.219.160.7:443`** — consistent with repeated `Invoke-WebRequest` calls to **example.com** during the T1071.001 simulation.

![Outbound connection stats](screenshots/phase-5-detect-outbound-results.png)

---

### 5. Persistence — Registry Run key

```spl
index=endpoint EventCode=13 TargetObject="*\\Run\\*" earliest=-1h
| table _time, TargetObject, Details, Image
```

**Finding:** Sysmon Event 13 recorded creation of:

- **TargetObject:** `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\AtomicRedTeamPersistence`
- **Details:** `powershell.exe -WindowStyle Hidden -Command Start-Sleep 3600`
- **RuleName in raw event:** `T1060,RunKey`

![Registry Run key events](screenshots/phase-5-detect-run-key-results.png)

---

### Scope conclusion

Activity limited to a single lab VM. No other hosts in the environment. No evidence of credential dumping (T1003 was intentionally excluded from this lab). Chain is consistent with a scripted attack simulation, not live malware.

---

## Containment and remediation

| Action | Rationale | Lab equivalent |
|---|---|---|
| **Isolate host** | Stop C2 and prevent lateral movement | Shut down VM or disconnect UTM network adapter |
| **Disable targeted account** | Stop attacker session if compromise confirmed | Disable or reset `baduser`; review `analyst` session |
| **Block destination IPs** | Stop beaconing to known C2 | Host or network firewall block on beacon destinations |
| **Remove persistence** | Prevent re-execution at logon | Delete `AtomicRedTeamPersistence` Run key value |
| **Preserve evidence** | Support forensics / reporting | UTM snapshot before cleanup; export Splunk events from `index=endpoint` |

**Recommended order (production):** isolate → preserve snapshot → disable account → block IOCs → remove persistence → escalate to Tier 2.

**Lab cleanup:**

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "AtomicRedTeamPersistence" -ErrorAction SilentlyContinue
```

Restore VM from the clean UTM clone taken before Phase 3 if a full reset is preferred.

---

## MITRE ATT&CK mapping

| Stage | Tactic | Technique | ID | Observable |
|---|---|---|---|---|
| Initial Access | Credential Access | Brute Force: Password Guessing | T1110.001 | Event 4625 burst |
| Execution | Execution | PowerShell | T1059.001 | Sysmon Event 1, `-EncodedCommand` |
| Command and Control | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Sysmon Event 3, HTTP/HTTPS from PowerShell |
| Persistence | Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | Sysmon Event 13, `\Run\` modification |

---

## Indicators of compromise (IOCs)

| Type | Value |
|---|---|
| Account | `baduser` (target of failed logons) |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AtomicRedTeamPersistence` |
| Process | `powershell.exe` with `-EncodedCommand` |
| Network | Outbound HTTP/HTTPS from PowerShell to CDN/resolver IPs associated with **example.com** beacon simulation |
| Host | `WIN-K1DGK4BA0UM` |

---

## Lessons learned

1. **Pipeline validation beats assumption.** Security events flowed while Sysmon did not, until `errorCode=5` in `splunkd.log` revealed an access-denied subscription failure. See [Phase 5 troubleshooting](phase-5-alerting.md#roadblocks-before-alerting-could-work).

2. **Clock sync matters for alerting.** VM time skew caused searches and alerts to miss recent events until `w32tm /resync` aligned timestamps with the indexer.

3. **Scheduled vs real-time alerts behave differently.** Real-time alerts appeared within a minute; the brute force alert waited for the next five-minute cron slot. Analysts need to know which is which when judging response time.

4. **Correlate stages, not just single events.** A complete story chains 4625 → execution → outbound → persistence. Individual alerts are entry points; the incident report ties them together.

5. **Apple Silicon lab constraints are real.** Sysmon64a, XML rendering for the Sysmon channel, and running the forwarder as Local System were all required on Windows 11 ARM — worth documenting for anyone reproducing this environment.

---

## Appendix — supporting screenshots

| Document | Screenshot |
|---|---|
| All alerts fired | [phase-5-triggered-alerts-all-fired.png](screenshots/phase-5-triggered-alerts-all-fired.png) |
| Alert configurations | [phase-5-alerting.md](phase-5-alerting.md) |
| Attack re-run commands | [phase-5-attacks-rerun-vm.png](screenshots/phase-5-attacks-rerun-vm.png) |
| Sysmon pipeline fix | [phase-5-roadblock-sysmon-errorcode5.png](screenshots/phase-5-roadblock-sysmon-errorcode5.png) |

---

Back to [documentation index](README.md) · Previous: [Phase 5 — Alerting](phase-5-alerting.md)
