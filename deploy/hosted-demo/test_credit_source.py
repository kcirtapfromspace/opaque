"""Validate generated portfolio aggregates and the tenant's source boundary."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("credit_source_under_test", Path(__file__).with_name("credit_source.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CreditSourceTests(unittest.TestCase):
    def source(self, tenant="demo-a", credential="private-source-a"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        source = c.CreditSource(0, tenant, credential, directory.name, clock=lambda: 10_000, produce=False)
        threading.Thread(target=source.serve_forever, daemon=True).start()
        self.addCleanup(source.server_close)
        self.addCleanup(source.shutdown)
        return source

    def request(self, source, body=None, credential="private-source-a", path="/v1/metrics/query"):
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        request = urllib.request.Request(f"http://127.0.0.1:{source.server_port}" + path,
                                         data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_aggregates_represent_applications_and_routing_flags(self):
        source = self.source()
        source.events.extend([(9_930, True, True), (9_950, False, False), (9_990, True, False), (10_000, True, True)])
        status, result = self.request(source, {"metrics": list(c.ALLOWED_METRICS), "window_secs": 60})
        self.assertEqual(status, 200)
        self.assertEqual(result["tenant_id"], "demo-a")
        values = {row["name"]: row["value"] for row in result["metrics"]}
        self.assertEqual(values["credit_applications_per_minute"], 3)
        self.assertAlmostEqual(values["manual_review_rate_percent"], 200 / 3)
        self.assertAlmostEqual(values["identity_mismatch_rate_percent"], 100 / 3)
        self.assertTrue(all(row["count"] == 3 for row in result["metrics"]))
        self.assertEqual(result["watermark"], 10_000)
        self.assertEqual(set(result), {"tenant_id", "window_secs", "as_of", "watermark", "metrics"})

    def test_tenant_credential_cannot_read_another_source(self):
        first = self.source()
        second = self.source("demo-b", "private-source-b")
        for source, credential in [(first, None), (first, "private-source-b"), (second, "private-source-a")]:
            self.assertEqual(self.request(source, {"metrics": [c.ALLOWED_METRICS[0]], "window_secs": 60}, credential)[0], 401)
            self.assertEqual(source.queries, 0)

    def test_raw_records_tenant_overrides_unlicensed_metrics_and_sql_are_rejected(self):
        source = self.source()
        good = {"metrics": [c.ALLOWED_METRICS[0]], "window_secs": 60}
        cases = [{**good, "tenant_id": "demo-b"}, {**good, "sql": "select * from borrowers"},
                 {**good, "fields": ["ssn"]}, {**good, "metrics": ["average_credit_score"]},
                 {**good, "metrics": ["requests_per_second"]}, {**good, "metrics": [c.ALLOWED_METRICS[0]] * 2},
                 {**good, "window_secs": True}, {**good, "window_secs": 301}, [good]]
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(self.request(source, body)[0], 400)
        for path in ["/borrowers", "/export", "/v1/metrics/query?tenant=demo-b"]:
            self.assertEqual(self.request(source, good, path=path)[0], 404)
        self.assertEqual(source.queries, 0)

    def test_generator_changes_observed_signals_without_personal_records(self):
        source = self.source()
        signals = set()
        for tick in range(1, 200):
            source.clock = lambda tick=tick: 10_000 + tick / 2
            source.tick()
            if tick % 20 == 0:
                values = source.aggregate(list(c.ALLOWED_METRICS), 10)
                signals.add(tuple(round(row["value"], 2) for row in values["metrics"]))
                for row in values["metrics"][1:]:
                    self.assertTrue(0 <= row["value"] <= 100)
        self.assertGreater(len(signals), 4)
        self.assertTrue(all(len(row) == 7 and type(row[1]) is bool and type(row[2]) is bool for row in source.events))
        evidence = json.loads((source.directory / "source-evidence.json").read_text())
        self.assertFalse(evidence["borrower_records_present"])
        self.assertFalse(evidence["raw_rows_exposed"])
        self.assertFalse(evidence["credit_decisions_enabled"])

    def portfolio_source(self):
        source = self.source()
        source.history_start = 2_790
        source.events.extend([
            (8_210, False, False, "web", "west", "auto_loan", 1000),
            (9_000, True, False, "mobile", "west", "auto_loan", 2000),
            (9_400, True, True, "mobile", "west", "auto_loan", 3000),
            (9_800, False, False, "web", "northeast", "personal_loan", 1000),
            (10_000, True, False, "partner", "midwest", "credit_card", 5000),
        ])
        return source

    def portfolio_request(self, source, **changes):
        body = {"view": "summary", "window_secs": 900, "measures": ["application_count", "manual_review_rate_percent",
                "identity_mismatch_rate_percent", "mean_processing_seconds"], **changes}
        return self.request(source, body, path="/v1/portfolio/query")

    def test_portfolio_summary_and_filtered_breakdown_use_actual_events(self):
        source = self.portfolio_source()
        status, result = self.portfolio_request(source)
        self.assertEqual(status, 200)
        row = result["rows"][0]
        self.assertEqual(row["sample_count"], 3)
        self.assertEqual(row["values"]["application_count"], 3)
        self.assertAlmostEqual(row["values"]["manual_review_rate_percent"], 200 / 3)
        self.assertAlmostEqual(row["values"]["mean_processing_seconds"], 3)
        self.assertEqual((result["watermark"], result["as_of"]), (10_000, 10_000))
        status, result = self.portfolio_request(source, view="breakdown", dimension="channel", filters={"region": "west"})
        self.assertEqual(status, 200)
        rows = {r["key"]: r for r in result["rows"]}
        self.assertEqual(rows["mobile"]["values"]["manual_review_rate_percent"], 100)
        self.assertEqual(rows["web"]["sample_count"], 0)
        self.assertIsNone(rows["web"]["values"]["mean_processing_seconds"])
        self.assertEqual(rows["web"]["values"]["application_count"], 0)
        self.assertEqual(sum(r["sample_count"] for r in result["rows"]), 1)
        status, counts = self.portfolio_request(source, measures=["application_count", "manual_review_count", "identity_mismatch_count"])
        self.assertEqual(status, 200)
        self.assertEqual(counts["rows"][0]["values"], {"application_count": 3, "manual_review_count": 2, "identity_mismatch_count": 1})

    def test_portfolio_trends_partition_window_and_comparisons_have_correct_units(self):
        source = self.portfolio_source()
        status, result = self.portfolio_request(source, view="trend")
        self.assertEqual(status, 200)
        rows = result["rows"]
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(r["sample_count"] for r in rows), 3)
        self.assertEqual(rows[0]["period_start"], 9_100)
        self.assertEqual(rows[-1]["period_end"], 10_000)
        self.assertTrue(all(a["period_end"] == b["period_start"] for a, b in zip(rows, rows[1:])))
        status, result = self.portfolio_request(source, view="comparison")
        self.assertEqual(status, 200)
        values = {r["measure"]: r for r in result["comparison"]}
        count = values["application_count"]
        self.assertEqual((count["current"], count["previous"], count["delta"], count["relative_percent"]), (3, 2, 1, 50))
        self.assertEqual(values["manual_review_rate_percent"]["delta_unit"], "percentage_points")
        self.assertAlmostEqual(values["manual_review_rate_percent"]["delta"], 200 / 3 - 50)
        self.assertEqual(values["mean_processing_seconds"]["delta_unit"], "seconds")

    def test_portfolio_denies_foreign_authority_raw_queries_and_unavailable_history(self):
        source = self.portfolio_source()
        good = {"view": "summary", "window_secs": 900, "measures": ["application_count"]}
        cases = [{**good, "tenant_id": "demo-b"}, {**good, "sql": "select * from data"},
                 {**good, "view": "records"}, {**good, "dimension": "channel"},
                 {**good, "view": "breakdown", "dimension": "ssn"},
                 {**good, "measures": ["average_credit_score"]}, {**good, "window_secs": 86400},
                 {**good, "measures": list(c.PORTFOLIO_MEASURES)},
                 {**good, "window_secs": True}, {**good, "measures": ["application_count"] * 2},
                 {**good, "filters": {"tenant": "demo-b"}}, {**good, "filters": {"channel": "*"}},
                 {**good, "filters": {"channel": ["web"]}}, {**good, "filters": None}]
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(self.request(source, body, path="/v1/portfolio/query")[0], 400)
        self.assertEqual(self.request(source, good, credential="foreign", path="/v1/portfolio/query")[0], 401)
        source.history_start = 9_500
        self.assertEqual(self.request(source, good, path="/v1/portfolio/query")[0], 400)
        self.assertEqual(source.queries, 0)

    def test_exact_period_boundaries_and_future_events_are_not_double_counted(self):
        source = self.portfolio_source()
        source.events.clear()
        source.events.extend((at, False, False, "web", "northeast", "auto_loan", 1000)
                             for at in (8_200, 9_100, 9_100.5, 9_250, 10_000, 10_001))
        status, trend = self.portfolio_request(source, view="trend", measures=["application_count"])
        self.assertEqual(status, 200)
        self.assertEqual([row["sample_count"] for row in trend["rows"]], [2, 0, 0, 0, 0, 1])
        self.assertEqual(trend["watermark"], 10_000)
        status, comparison = self.portfolio_request(source, view="comparison", measures=["application_count"])
        self.assertEqual(status, 200)
        self.assertEqual([row["sample_count"] for row in comparison["rows"]], [3, 1])
        status, empty = self.portfolio_request(source, view="comparison", filters={"region": "southeast"})
        self.assertEqual(status, 200)
        self.assertEqual([row["sample_count"] for row in empty["rows"]], [0, 0])
        for item in empty["comparison"]:
            self.assertIsNone(item["relative_percent"])
            self.assertEqual(item["delta"], 0 if item["measure"] == "application_count" else None)

    def test_seeded_history_contains_reproducible_investigable_patterns_and_live_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            source = c.CreditSource(0, "demo-pattern", "private", directory, clock=lambda: 10_000,
                                    produce=False, seed_history=True)
            self.addCleanup(source.server_close)
            self.assertGreater(source.generated, 50_000)
            recent = source.portfolio({"view": "breakdown", "window_secs": 900,
                                       "measures": ["identity_mismatch_rate_percent"], "dimension": "channel"})
            rates = {r["key"]: r["values"]["identity_mismatch_rate_percent"] for r in recent["rows"]}
            self.assertGreater(rates["mobile"], rates["web"] + 10)
            workload = source.portfolio({"view": "breakdown", "window_secs": 900,
                                         "measures": ["manual_review_count", "manual_review_rate_percent"], "dimension": "channel"})
            self.assertEqual(max(workload["rows"], key=lambda row: row["values"]["manual_review_count"])["key"], "web")
            self.assertEqual(max(workload["rows"], key=lambda row: row["values"]["manual_review_rate_percent"])["key"], "mobile")
            comparison = source.portfolio({"view": "comparison", "window_secs": 900,
                                           "measures": ["identity_mismatch_rate_percent"], "filters": {"channel": "mobile"}})
            self.assertGreater(comparison["comparison"][0]["delta"], 10)
            source.clock = lambda: 10_001
            before = source.generated
            source.tick()
            self.assertGreater(source.generated, before)
            self.assertEqual(source.portfolio({"view": "summary", "window_secs": 3600,
                                               "measures": ["application_count"]})["watermark"], 10_001)
            for tick in range(1, 201):
                source.clock = lambda tick=tick: 10_001 + tick / 2
                source.tick()
            longest = source.portfolio({"view": "comparison", "window_secs": 3600,
                                        "measures": ["application_count"]})
            self.assertLessEqual(longest["history_start"], longest["as_of"] - 7200)
            self.assertEqual(len(longest["rows"]), 2)
            self.assertTrue(all(row["sample_count"] > 30_000 for row in longest["rows"]))
            self.assertGreaterEqual(source.events[0][0], 10_101 - c.RETENTION_SECS)


if __name__ == "__main__":
    unittest.main()
