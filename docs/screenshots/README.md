# Screenshot catalog

Phase 5 and Phase 6 figures, renamed for GitHub-friendly paths.

## Detections (prerequisites for alerting)

| File | Description |
|---|---|
| `phase-5-detect-brute-force-results.png` | `EventCode=4625` failed logon burst on `WIN-K1DGK4BA0UM` |
| `phase-5-detect-brute-force-save.png` | Saving T1110.001 detection as a report |
| `phase-5-detect-encoded-powershell-results.png` | Sysmon Event 1 with `-EncodedCommand` |
| `phase-5-detect-outbound-results.png` | Sysmon Event 3 — PowerShell outbound connections |
| `phase-5-detect-outbound-save.png` | Saving T1071.001 detection report |
| `phase-5-detect-run-key-results.png` | Sysmon Event 13 — `AtomicRedTeamPersistence` Run key |

## Alert configuration

| File | Description |
|---|---|
| `phase-5-alert-brute-force-config-v1.png` | First alert attempt — Custom trigger parse error |
| `phase-5-alert-brute-force-config-final.png` | Final T1110.001 scheduled alert (cron `*/5`, High) |
| `phase-5-alert-encoded-powershell-config.png` | T1059.001 real-time alert (Critical) |
| `phase-5-alert-run-key-config.png` | T1547.001 scheduled alert (High) |
| `phase-5-alerts-list-enabled.png` | All four alerts enabled in Splunk |

## Validation

| File | Description |
|---|---|
| `phase-5-triggered-alerts-all-fired.png` | Triggered Alerts — all four MITRE alerts fired |
| `phase-5-attacks-rerun-vm.png` | Attack re-run commands in VM PowerShell |

## Troubleshooting

| File | Description |
|---|---|
| `phase-5-roadblock-sysmon-errorcode5.png` | `splunkd.log` — Sysmon channel `errorCode=5` Access Denied |

Original captures are in `~/Splunk Lab/` on the lab machine.
