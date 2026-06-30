# Phase 3: Attack Simulation

This is where I actually ran stuff on the VM to generate suspicious logs. Four techniques, all mapped to MITRE IDs because that's how the detections and alerts are labeled later.

I snapped the VM first so I could roll back if I broke something.

The scripts are in [`scripts/attacks/`](../../scripts/attacks/) in the repo. I copied that folder to `C:\Lab\attacks` on the VM and ran them from Admin PowerShell.

| MITRE | Script | What showed up in logs |
|---|---|---|
| T1110.001 | `T1110.001-brute-force.ps1` | Security event 4625 |
| T1059.001 | `T1059.001-encoded-powershell.ps1` | Sysmon event 1 |
| T1071.001 | `T1071.001-web-beacon.ps1` | Sysmon event 3 |
| T1547.001 | `T1547.001-run-key.ps1` | Sysmon event 13 |

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\Lab\attacks
.\T1110.001-brute-force.ps1
.\T1059.001-encoded-powershell.ps1
.\T1071.001-web-beacon.ps1
.\T1547.001-run-key.ps1
```

Cleanup after the run key test: `.\remove-run-key.ps1`

---

## Brute force (T1110.001)

The logins fail on purpose. Each failure still creates a 4625 in the Security log.

```spl
index=endpoint EventCode=4625
```

![4625 results](screenshots/phase-3-brute-force-4625.png)

---

## Encoded PowerShell (T1059.001)

```spl
index=endpoint EventCode=1 CommandLine="*EncodedCommand*"
```

![EncodedCommand in Sysmon](screenshots/phase-3-encoded-powershell.png)

---

## Web beacon (T1071.001)

```spl
index=endpoint EventCode=3 Image="*powershell.exe"
```

![outbound connections](screenshots/phase-5-detect-outbound-results.png)

---

## Run key persistence (T1547.001)

```spl
index=endpoint EventCode=13 TargetObject="*\\Run\\*"
```

![Run key in Sysmon](screenshots/phase-3-run-key-event13.png)

---

## Quick check on the VM itself

When Splunk looked empty I'd check Sysmon locally first:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 | Group-Object Id
```

![local Sysmon counts](screenshots/phase-3-sysmon-local-counts.png)

If events exist on the VM but not in Splunk, it's a forwarder problem — not the attack script.

---

Next: [Phase 4 — Detections](phase-4-detections.md) · [Phase 2](phase-2-baseline-dashboard.md)
