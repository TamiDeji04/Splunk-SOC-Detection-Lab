# Lab scripts

## Attack simulations (Windows VM)

Run from **Admin PowerShell**. Copy this folder to the VM first (USB, shared folder, or paste into `C:\Lab\attacks`).

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\Lab\attacks
.\T1110.001-brute-force.ps1
.\T1059.001-encoded-powershell.ps1
.\T1071.001-web-beacon.ps1
.\T1547.001-run-key.ps1
```

| Script | MITRE |
|---|---|
| `attacks/T1110.001-brute-force.ps1` | T1110.001 |
| `attacks/T1059.001-encoded-powershell.ps1` | T1059.001 |
| `attacks/T1071.001-web-beacon.ps1` | T1071.001 |
| `attacks/T1547.001-run-key.ps1` | T1547.001 |
| `attacks/remove-run-key.ps1` | cleanup after T1547.001 |

## Sysmon config

`sysmon/sysmonconfig-export.xml` — [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (same file used on the VM).

Install on Windows ARM:

```powershell
Sysmon64a.exe -accepteula -i C:\path\to\sysmonconfig-export.xml
```

## Splunk detections

[`../splunk/savedsearches.conf`](../splunk/savedsearches.conf) — four saved search stanzas matching the lab detections.
