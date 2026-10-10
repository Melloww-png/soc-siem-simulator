from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
import time

from flask import Flask, abort, redirect, render_template_string, url_for

app = Flask(__name__)
app.config["DATABASE"] = Path(__file__).with_name("simulator.db")

GROUP = ("demo.account", "LAB-PC-01", "192.0.2.25")
WINDOW = 300


@contextmanager
def database():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db():
    with database() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                account TEXT NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                outcome TEXT NOT NULL
                    CHECK(outcome IN ('success', 'failure'))
            );

            CREATE INDEX IF NOT EXISTS login_window
            ON events(account, host, source_ip, outcome, timestamp);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                detected_at INTEGER NOT NULL,
                account TEXT NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                evidence_ids TEXT NOT NULL,
                first_event_id INTEGER NOT NULL
            );
        """)


def record_event(connection, timestamp, outcome, account, host, source_ip):
    connection.execute(
        """INSERT INTO events
           (timestamp, account, host, source_ip, outcome)
           VALUES (?, ?, ?, ?, ?)""",
        (timestamp, account, host, source_ip, outcome),
    )

    if outcome != "failure":
        return None

    evidence = connection.execute(
        """SELECT id FROM events
           WHERE account = ? AND host = ? AND source_ip = ?
           AND outcome = 'failure'
           AND timestamp BETWEEN ? AND ?
           ORDER BY timestamp DESC, id DESC
           LIMIT 5""",
        (account, host, source_ip, timestamp - WINDOW, timestamp),
    ).fetchall()

    if len(evidence) < 5:
        return None

    existing = connection.execute(
        """SELECT id FROM alerts
           WHERE account = ? AND host = ? AND source_ip = ?
           AND detected_at BETWEEN ? AND ?
           LIMIT 1""",
        (account, host, source_ip, timestamp - WINDOW, timestamp),
    ).fetchone()

    if existing:
        return None

    ids = [row["id"] for row in evidence]

    cursor = connection.execute(
        """INSERT INTO alerts
           (detected_at, account, host, source_ip,
            evidence_ids, first_event_id)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            timestamp,
            account,
            host,
            source_ip,
            json.dumps(ids),
            min(ids),
        ),
    )

    return cursor.lastrowid


def prune(connection):
    connection.execute(
        """DELETE FROM events
           WHERE id NOT IN (
               SELECT id FROM events ORDER BY id DESC LIMIT 1000
           )"""
    )

    oldest = connection.execute(
        "SELECT MIN(id) FROM events"
    ).fetchone()[0]

    if oldest is not None:
        connection.execute(
            "DELETE FROM alerts WHERE first_event_id < ?",
            (oldest,),
        )

    connection.execute(
        """DELETE FROM alerts
           WHERE id NOT IN (
               SELECT id FROM alerts ORDER BY id DESC LIMIT 100
           )"""
    )


@app.template_filter("utc")
def utc(timestamp):
    return datetime.fromtimestamp(
        timestamp, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SOC Simulator</title>
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #f5f6f2;
            color: #252b26;
            font: 16px/1.6 "Trebuchet MS", sans-serif;
        }

        main {
            max-width: 1100px;
            margin: auto;
            padding: 48px 24px;
        }

        h1 {
            font-size: clamp(28px, 4vw, 42px);
            line-height: 1.2;
            margin: 8px 0 16px;
        }

        h2 {
            margin: 0 0 16px;
            font-size: 24px;
        }

        p {
            margin: 0 0 16px;
        }

        a {
            color: #49634e;
        }

        .label {
            color: #49634e;
            font-weight: bold;
        }

        section {
            margin-top: 40px;
            padding-top: 24px;
            border-top: 1px solid #cbd1c9;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin: 24px 0;
        }

        button {
            background: #49634e;
            color: #fff;
            border: 0;
            border-radius: 4px;
            padding: 12px 20px;
            font: inherit;
            cursor: pointer;
        }

        button:hover {
            text-decoration: underline;
        }

        a:focus-visible,
        button:focus-visible {
            outline: 3px solid #49634e;
            outline-offset: 4px;
        }

        .scroll {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th, td {
            padding: 12px;
            border-bottom: 1px solid #d9ded6;
            white-space: nowrap;
        }

        th {
            font-weight: bold;
        }

        .detail {
            max-width: 760px;
        }
    </style>
</head>
<body>
<main>
    <header>
        <p class="label">Simulated data · Local practice project</p>
        <h1>SOC Simulator</h1>
        <p>
            Generate fictional login events, review alerts,
            and inspect their evidence.
        </p>
    </header>

    {% if alert %}
        <section>
            <p>
                <a href="{{ url_for('dashboard') }}">
                    Back to dashboard
                </a>
            </p>

            <h2>Alert #{{ alert.id }}: Repeated failed logins</h2>
            <p>Detected at {{ alert.detected_at|utc }}</p>

            <p>
                <strong>Account:</strong> {{ alert.account }} ·
                <strong>Host:</strong> {{ alert.host }} ·
                <strong>Source IP:</strong> {{ alert.source_ip }}
            </p>

            <p class="detail">
                Five failures matched within a rolling five-minute
                window. This needs investigation: a forgotten password,
                a configuration issue, or an unauthorised login attempt
                could cause repeated failures. This alert alone does
                not prove an attack.
            </p>

            <h2>Supporting event timeline</h2>
            <p>
                The five qualifying events are shown oldest first.
                Events generated together share a timestamp and
                are ordered by event ID.
            </p>
    {% else %}
        <div class="actions">
            <form method="post"
                  action="{{ url_for('generate', scenario='normal') }}">
                <button type="submit">Generate normal login</button>
            </form>

            <form method="post"
                  action="{{ url_for('generate', scenario='failed') }}">
                <button type="submit">Generate 5 failed logins</button>
            </form>
        </div>

        <p>
            {{ event_count }} retained events ·
            {{ alert_count }} retained alerts
        </p>

        <section>
            <h2>Alerts</h2>

            {% for item in alerts %}
                <p>
                    <a href="{{ url_for('alert_detail', alert_id=item.id) }}">
                        Alert #{{ item.id }}: Repeated failed logins
                    </a>
                    — {{ item.detected_at|utc }}
                </p>
            {% else %}
                <p>No alerts recorded yet.</p>
            {% endfor %}
        </section>

        <section>
            <h2>Recent login events</h2>
            <p>
                Showing the latest 50 events.
                The SQLite database retains at most 1,000.
            </p>
    {% endif %}

            <div class="scroll">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Time</th>
                            <th>Account</th>
                            <th>Host</th>
                            <th>Source IP</th>
                            <th>Outcome</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for event in events %}
                            <tr>
                                <td>{{ event.id }}</td>
                                <td>{{ event.timestamp|utc }}</td>
                                <td>{{ event.account }}</td>
                                <td>{{ event.host }}</td>
                                <td>{{ event.source_ip }}</td>
                                <td>{{ event.outcome }}</td>
                            </tr>
                        {% else %}
                            <tr>
                                <td colspan="6">
                                    No events recorded yet.
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>

    <section>
        <h2>Detection rule</h2>

        <p class="detail">
            At least five failed logins for the exact same account,
            host, and source IP in the last 300 seconds.
            Both time boundaries are included.
            Successful logins do not count.
            Matching failures do not need to be consecutive.
        </p>

        <p class="detail">
            For each matching account, host, and IP, additional alerts
            are suppressed for five minutes after an alert.
            Alerts preserve five qualifying events as evidence.
            Older events and alerts are automatically removed;
            an alert is also removed if its evidence expires.
        </p>

        <p>
            This version processes the generated scenarios
            in event-time order.
        </p>
    </section>
</main>
</body>
</html>
"""


@app.get("/")
def dashboard():
    with database() as connection:
        events = connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 50"
        ).fetchall()

        alerts = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 100"
        ).fetchall()

        event_count = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        alert_count = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

    return render_template_string(
        PAGE,
        alert=None,
        events=events,
        alerts=alerts,
        event_count=event_count,
        alert_count=alert_count,
    )


@app.post("/generate/<scenario>")
def generate(scenario):
    if scenario not in ("normal", "failed"):
        abort(404)

    timestamp = int(time.time())

    with database() as connection:
        for _ in range(1 if scenario == "normal" else 5):
            record_event(
                connection,
                timestamp,
                "success" if scenario == "normal" else "failure",
                *GROUP,
            )

        prune(connection)

    return redirect(url_for("dashboard"))


@app.get("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    with database() as connection:
        alert = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()

        if alert is None:
            abort(404)

        ids = json.loads(alert["evidence_ids"])
        placeholders = ",".join("?" for _ in ids)

        events = connection.execute(
            f"""SELECT * FROM events
                WHERE id IN ({placeholders})
                ORDER BY timestamp, id""",
            ids,
        ).fetchall()

    return render_template_string(
        PAGE,
        alert=alert,
        events=events,
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)