# SOC/SIEM Simulator

An individual cybersecurity portfolio project built with Python,
Flask, and SQLite. Runs locally on Windows.

All security events are simulated. Alerts require investigation
and do not automatically prove an attack.

## Implemented

- Generate successful login events.
- Generate five failed logins for a dedicated fictional account.
- Store events in SQLite.
- Detect repeated failed logins.
- Open alerts to inspect five supporting events and their timeline.
- Display computed event and alert counts.
- Retain at most 1,000 events and 100 alerts.
- Remove alerts when their supporting evidence expires.

## Detection rule

Trigger when at least five failed logins occur within a rolling
300-second window for the same account, host, and source IP.

Both time boundaries are included. Successful logins do not count
and do not reset the window.

Additional alerts for the same account, host, and IP are suppressed
for 300 seconds after an alert, including the exact boundary.

The current generator supplies events in event-time order.
Handling delayed or out-of-order logs is outside this version.

## Run on Windows

Open the project folder in Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 in a browser.

The application creates simulator.db automatically.
Press Ctrl+C in the terminal to stop the server.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_detection.py
```

All 11 automated tests passed during initial Windows validation.

Tests cover:
- Successful logins and the four/five-failure threshold.
- Exact 300-second and excluded 301-second boundaries.
- Separation by account, host, and source IP.
- Successful logins between failures.
- Alerts caused by legitimate password mistakes.
- Duplicate suppression and later alerts.
- Dashboard routes, evidence selection, and persistence.
- Event and alert retention limits.

Tests use temporary databases.

These results validate the specified simulated cases.
They do not measure real-world detection accuracy or performance.

## Planned

- Windows and Linux event scenarios.
- Event filtering and search.
- Activity charts.
- Alert severity and review status.
- Investigation notes and conclusions.
- Additional tested detection rules.
- Appropriate MITRE ATT&CK mappings.
- Repeatable scenarios with explicitly measured results.