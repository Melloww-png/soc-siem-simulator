import json
from pathlib import Path
import tempfile
import unittest

import app as simulator


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_database = simulator.app.config["DATABASE"]
        simulator.app.config["DATABASE"] = (
            Path(self.temp.name) / "test.db"
        )
        simulator.init_db()
        self.client = simulator.app.test_client()

    def tearDown(self):
        simulator.app.config["DATABASE"] = self.previous_database
        self.temp.cleanup()

    def failure(self, connection, timestamp, group=simulator.GROUP):
        return simulator.record_event(
            connection, timestamp, "failure", *group
        )

    def counts(self):
        with simulator.database() as connection:
            events = connection.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            alerts = connection.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

        return events, alerts

    def test_normal_logins_do_not_alert(self):
        with simulator.database() as connection:
            for _ in range(10):
                simulator.record_event(
                    connection, 1000, "success", *simulator.GROUP
                )

        self.assertEqual(self.counts(), (10, 0))

    def test_four_failures_do_not_alert_fifth_does(self):
        with simulator.database() as connection:
            for timestamp in (1000, 1010, 1020, 1030):
                self.assertIsNone(
                    self.failure(connection, timestamp)
                )

            self.assertIsNotNone(
                self.failure(connection, 1040)
            )

        self.assertEqual(self.counts(), (5, 1))

    def test_exact_300_second_boundary_is_included(self):
        with simulator.database() as connection:
            for timestamp in (1000, 1100, 1200, 1250):
                self.failure(connection, timestamp)

            self.assertIsNotNone(
                self.failure(connection, 1300)
            )

    def test_301_seconds_is_outside_window(self):
        with simulator.database() as connection:
            for timestamp in (1000, 1100, 1200, 1250):
                self.failure(connection, timestamp)

            self.assertIsNone(
                self.failure(connection, 1301)
            )

        self.assertEqual(self.counts(), (5, 0))

    def test_each_matching_field_separates_groups(self):
        for field in range(3):
            with self.subTest(field=field):
                with simulator.database() as connection:
                    connection.execute("DELETE FROM alerts")
                    connection.execute("DELETE FROM events")

                    for _ in range(4):
                        self.failure(connection, 1000)

                    group = list(simulator.GROUP)
                    group[field] = "different-value"

                    self.assertIsNone(
                        self.failure(connection, 1000, group)
                    )

                self.assertEqual(self.counts(), (5, 0))

    def test_normal_activity_can_trigger_rule(self):
        # Scenario: a legitimate user repeatedly mistypes a password.
        # The rule sees failures, not the user's intention.
        with simulator.database() as connection:
            for timestamp in (1000, 1010, 1020, 1030, 1040):
                self.failure(connection, timestamp)

        self.assertEqual(self.counts(), (5, 1))

    def test_success_between_failures_does_not_reset_window(self):
        with simulator.database() as connection:
            for _ in range(4):
                self.failure(connection, 1000)

            simulator.record_event(
                connection, 1001, "success", *simulator.GROUP
            )

            self.assertIsNotNone(
                self.failure(connection, 1002)
            )

    def test_suppression_and_later_new_alert(self):
        with simulator.database() as connection:
            for _ in range(5):
                self.failure(connection, 1000)

            for _ in range(5):
                self.failure(connection, 1001)

            alert_count = connection.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            self.assertEqual(alert_count, 1)

            for _ in range(5):
                self.failure(connection, 1301)

        self.assertEqual(self.counts(), (15, 2))

    def test_full_dashboard_flow_and_persistence(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Simulated data", response.data)

        self.client.post("/generate/normal")
        self.assertEqual(self.counts(), (1, 0))

        self.client.post("/generate/failed")
        self.assertEqual(self.counts(), (6, 1))

        # Initialising an existing database must preserve its records.
        simulator.init_db()
        self.assertEqual(self.counts(), (6, 1))

        response = self.client.get("/alerts/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Supporting event timeline", response.data)

        with simulator.database() as connection:
            row = connection.execute(
                "SELECT evidence_ids FROM alerts"
            ).fetchone()

            evidence = json.loads(row["evidence_ids"])
            self.assertEqual(len(evidence), 5)
            self.assertEqual(len(set(evidence)), 5)

            # Event 1 was the successful login.
            self.assertNotIn(1, evidence)

        self.assertEqual(
            self.client.get("/alerts/999").status_code, 404
        )
        self.assertEqual(
            self.client.post("/generate/unknown").status_code, 404
        )
        self.assertEqual(
            self.client.get("/generate/failed").status_code, 405
        )

    def test_event_cap_removes_alert_with_expired_evidence(self):
        with simulator.database() as connection:
            for _ in range(5):
                self.failure(connection, 1000)

            for timestamp in range(1000, 2001):
                simulator.record_event(
                    connection, timestamp, "success", *simulator.GROUP
                )

            simulator.prune(connection)

        self.assertEqual(self.counts(), (1000, 0))

    def test_alert_cap(self):
        with simulator.database() as connection:
            for batch in range(110):
                for _ in range(5):
                    self.failure(connection, 1000 + batch * 301)

                simulator.prune(connection)

        self.assertEqual(self.counts(), (550, 100))


if __name__ == "__main__":
    unittest.main()