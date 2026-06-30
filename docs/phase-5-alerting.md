# Phase 5: Alerting

Saved searches are useful but you still have to run them yourself. Alerts are what actually pop up when something matches — that's the part I cared about for this lab.

Splunk's free trial includes alerting. After 60 days it drops to the free license and you lose scheduled/real-time alerts, so I did this whole phase while the trial was still active.

---

## Problems I hit before alerts would work

Most of this was already covered in Phase 1, but it mattered here because alerts looked broken when the data pipeline was broken.

**Sysmon not in Splunk (errorCode=5)** — Security events worked, Sysmon didn't. Forwarder looked healthy. Log file said access denied on the Sysmon channel. Fixed by running the forwarder as Local System + `renderXml = true`. Details in [Phase 1](phase-1-environment.md).

![errorCode=5](screenshots/phase-5-roadblock-sysmon-errorcode5.png)

**VM clock off** — "Last 15 minutes" showed nothing, "all time" had data. `w32tm /resync` fixed it.

**Wrong Splunk page for port 9997** — I was on the forwarding screen, not receiving. Receiving only wants the port number.

**Alert save error** — Splunk said `Unknown search command '0'`. I had the trigger set to Custom instead of **Number of Results > 0**.

![bad alert config](screenshots/phase-5-alert-brute-force-config-v1.png)

---

## Turning searches into alerts

I opened each saved report and did Save As → Alert. Four total:

![all alerts enabled](screenshots/phase-5-alerts-list-enabled.png)

### Brute force — scheduled every 5 min

Runs on a cron because the search needs to count failures over a window. Real-time would fire on every single 4625.

| Setting | Value |
|---|---|
| Schedule | `*/5 * * * *` |
| Time range | Last 5 minutes |
| Trigger | Number of results > 0 |
| Severity | High |

![brute force alert](screenshots/phase-5-alert-brute-force-config-final.png)

### Encoded PowerShell — real-time

Any hit is bad enough to alert immediately.

| Setting | Value |
|---|---|
| Type | Real-time |
| Trigger | Results > 0 in 1 minute |
| Severity | Critical |

![powershell alert](screenshots/phase-5-alert-encoded-powershell-config.png)

### Run key — scheduled every 1 min

![run key alert](screenshots/phase-5-alert-run-key-config.png)

### Outbound — real-time, medium severity

No screenshot of the config page but it showed up in Triggered Alerts with the others.

---

## Testing — re-ran the attacks

I ran all four attack scripts again in the VM:

![rerun in VM](screenshots/phase-5-attacks-rerun-vm.png)

Then checked **Activity → Triggered Alerts** on the Mac. All four fired:

| Time | Alert |
|---|---|
| 20:11:50 | Encoded PowerShell (real-time) |
| 20:12:25 | Suspicious Outbound (real-time) |
| 20:13:06 | Registry Run Key |
| 20:15:00 | Brute Force (scheduled — showed up last because it waits for the 5-min cron) |

![all fired](screenshots/phase-5-triggered-alerts-all-fired.png)

The brute force one being last confused me at first. It's scheduled — it doesn't fire the second the attack runs, it fires on the next 5-minute mark. Not a bug.

---

## If I did this again

- I'd probably add email or Slack as an alert action, not just Triggered Alerts
- The `count > 5` threshold is only tuned for my test script, not a real environment
- After a brute force alert I'd also look for a successful 4624 logon on the same host

---

Next: [Phase 6 — Incident Report](phase-6-incident-report.md) · [Phase 4](phase-4-detections.md)
