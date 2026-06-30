# Phase 6: Incident Report

**Report ID:** SOC-LAB-2026-001  
**Date:** June 29, 2026  
**Analyst:** Tamilo Eadedeji  
**Host:** `WIN-K1DGK4BA0UM` (Windows 11 VM in UTM)  
**SIEM:** Splunk Enterprise 10.4.0 on my Mac, `index=endpoint`  
**Note:** This is a lab simulation, not a real incident.

---

## Summary

I ran four attack simulations on my lab VM and all four Splunk alerts fired between 20:11 and 20:15 CDT on June 29:

1. Failed logon burst against `baduser` (T1110.001)
2. Encoded PowerShell (T1059.001)
3. Outbound HTTP from PowerShell (T1071.001)
4. Registry Run key named `AtomicRedTeamPersistence` (T1547.001)

Everything happened on the one VM. Nothing spread anywhere else — it's a disposable lab box.

---

## Timeline

| Time (CDT) | What happened |
|---|---|
| ~20:10 | Ran brute force script — 12 failed logons |
| 20:11:50 | Alert: Encoded PowerShell |
| 20:12:25 | Alert: Suspicious Outbound |
| 20:13:06 | Alert: Registry Run Key |
| ~20:13 | Ran the other three attack scripts |
| 20:15:00 | Alert: Brute Force (scheduled, so it was last) |

![triggered alerts](screenshots/phase-5-triggered-alerts-all-fired.png)

---

## What the alerts meant

| Alert | What it caught |
|---|---|
| Encoded PowerShell | `powershell.exe` with `-EncodedCommand` |
| Suspicious Outbound | PowerShell making outbound connections |
| Registry Run Key | New value under a Windows Run key |
| Brute Force | More than 5 failed logons in 5 minutes |

---

## What I checked after the alerts

### Brute force

```spl
index=endpoint EventCode=4625 earliest=-1h
| stats count by Account_Name, Source_Network_Address
| sort -count
```

24 failed logons for `baduser`, source `::1` (loopback — makes sense since I ran the script locally on the VM).

![brute force results](screenshots/phase-5-detect-brute-force-results.png)

### Successful logon?

```spl
index=endpoint EventCode=4624 earliest=-1h
| table _time, Account_Name, Logon_Type, Source_Network_Address
```

I didn't need a separate successful logon for this lab — the PowerShell scripts ran under my existing `analyst` session. In a real case I'd look for a 4624 right after a bunch of 4625s.

### Encoded PowerShell

```spl
index=endpoint EventCode=1 CommandLine="*EncodedCommand*" earliest=-1h
| table _time, User, Image, CommandLine
```

Two hits. User `analyst`, `-EncodedCommand` in the command line.

![encoded powershell](screenshots/phase-5-detect-encoded-powershell-results.png)

### Outbound traffic

```spl
index=endpoint EventCode=3 Image="*powershell.exe" earliest=-1h
| table _time, DestinationIp, DestinationPort
```

Connections to external IPs on 80/443 from my `Invoke-WebRequest` loop to example.com.

![outbound](screenshots/phase-5-detect-outbound-results.png)

### Run key

```spl
index=endpoint EventCode=13 TargetObject="*\\Run\\*" earliest=-1h
| table _time, TargetObject, Details
```

`AtomicRedTeamPersistence` under the Run key — exactly what my test script created.

![run key](screenshots/phase-5-detect-run-key-results.png)

---

## What I would do in a real environment

| Action | Why |
|---|---|
| Isolate the host | Stop anything still running / calling out |
| Disable the account | If someone actually got in |
| Block the outbound IPs | Stop beaconing |
| Delete the Run key | Remove persistence |
| Snapshot the VM | Keep logs/evidence before wiping |

**What I actually did in the lab:**

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "AtomicRedTeamPersistence" -ErrorAction SilentlyContinue
```

Or just restore the VM from the snapshot I took before Phase 3.

---

## MITRE mapping

| Stage | Technique | ID |
|---|---|---|
| Failed logons | Brute Force: Password Guessing | T1110.001 |
| Encoded PowerShell | PowerShell | T1059.001 |
| HTTP beacon | Application Layer Protocol: Web | T1071.001 |
| Run key | Registry Run Keys | T1547.001 |

---

## IOCs from this lab

| Type | Value |
|---|---|
| Account | `baduser` |
| Registry | `AtomicRedTeamPersistence` under Run key |
| Host | `WIN-K1DGK4BA0UM` |
| Network | Outbound HTTP/HTTPS from PowerShell (example.com test) |

---

## What I learned

1. Sysmon can be running on the VM and still not show up in Splunk — the errorCode=5 thing wasted a lot of my time.
2. VM clock being wrong makes recent searches look empty when data is actually there.
3. Scheduled alerts don't fire instantly. The brute force one was 4 minutes behind the real-time ones.
4. One alert alone doesn't tell the full story. The value is connecting brute force → execution → outbound → persistence.

---

[docs index](README.md) · [Phase 5](phase-5-alerting.md)
