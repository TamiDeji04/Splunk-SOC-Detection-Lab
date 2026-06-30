# Screenshot catalog

Renamed from `~/Splunk Lab/` for GitHub-friendly paths. Organized by phase.

---

## Phase 1 — Environment

| File | Description |
|---|---|
| `phase-1-crystalfetch-iso.png` | CrystalFetch — Windows 11 ARM ISO download |
| `phase-1-utm-summary.png` | UTM VM summary — ARM64, 4 GB RAM |
| `phase-1-windows-updates.png` | Fresh Windows 11 VM — Windows Update |
| `phase-1-network-test.png` | `Test-NetConnection` — TcpTestSucceeded on :9997 |
| `phase-1-add-monitor-failed.png` | UF `add monitor` error for event log channel |
| `phase-1-uf-inputs-conf.png` | `inputs.conf` stanzas + forwarder restart |
| `phase-1-uf-forward-server.png` | Active forward server `192.168.1.241:9997` |
| `phase-1-security-events-ingested.png` | `stats count by EventCode` — Security events in Splunk |
| `phase-5-roadblock-sysmon-errorcode5.png` | `splunkd.log` — Sysmon channel errorCode=5 (also Phase 1 roadblock) |

---

## Phase 2 — Baseline dashboard

| File | Description |
|---|---|
| `phase-2-timechart-eventcode.png` | `timechart count by EventCode` |
| `phase-2-soc-overview-edit.png` | SOC Overview dashboard — edit mode |
| `phase-2-soc-overview-panels.png` | SOC Overview — timechart + bar chart panels |

---

## Phase 3 — Attack simulation

| File | Description |
|---|---|
| `phase-3-brute-force-4625.png` | T1110.001 — 12 Event 4625 failed logons |
| `phase-3-sysmon-local-counts.png` | Local Sysmon Event 1/13 counts on VM |
| `phase-3-encoded-powershell.png` | T1059.001 — `-EncodedCommand` in Event 1 |
| `phase-3-run-key-event13.png` | T1547.001 — `AtomicRedTeamPersistence` Run key |
| `phase-5-detect-outbound-results.png` | T1071.001 — PowerShell outbound Event 3 |

---

## Phase 4 — Detections

| File | Description |
|---|---|
| `phase-5-detect-brute-force-results.png` | T1110.001 detection stats |
| `phase-5-detect-brute-force-save.png` | Saving brute force report |
| `phase-5-detect-encoded-powershell-results.png` | T1059.001 detection results |
| `phase-5-detect-outbound-save.png` | Saving T1071.001 report |
| `phase-5-detect-run-key-results.png` | T1547.001 detection results |

---

## Phase 5 — Alerting

| File | Description |
|---|---|
| `phase-5-alert-brute-force-config-v1.png` | First alert attempt — Custom trigger parse error |
| `phase-5-alert-brute-force-config-final.png` | Final T1110.001 scheduled alert |
| `phase-5-alert-encoded-powershell-config.png` | T1059.001 real-time alert (Critical) |
| `phase-5-alert-run-key-config.png` | T1547.001 scheduled alert |
| `phase-5-alerts-list-enabled.png` | All four alerts enabled |
| `phase-5-triggered-alerts-all-fired.png` | Triggered Alerts — all four fired |
| `phase-5-attacks-rerun-vm.png` | Attack re-run in VM PowerShell |

---

Original captures remain in `~/Splunk Lab/` on the lab machine.
