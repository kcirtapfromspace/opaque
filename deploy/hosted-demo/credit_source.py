"""Synthetic, tenant-bound loan application aggregates for the hosted demo.

Events contain generated operational attributes, never borrower records,
identifiers, credit scores, or credit decisions. Historical events are seeded
synthetic data; new events continue the same scenario while the lease is live.
"""
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import hashlib
import json
from pathlib import Path
import random
import threading
import time

ALLOWED_METRICS = (
    "credit_applications_per_minute",
    "manual_review_rate_percent",
    "identity_mismatch_rate_percent",
)
PORTFOLIO_MEASURES = ("application_count", "manual_review_count", "identity_mismatch_count",
                      "manual_review_rate_percent", "identity_mismatch_rate_percent", "mean_processing_seconds")
PORTFOLIO_DIMENSIONS = {"channel": ("web", "mobile", "partner"),
                        "region": ("northeast", "southeast", "midwest", "west"),
                        "product": ("personal_loan", "auto_loan", "credit_card")}
PORTFOLIO_WINDOWS = (60, 300, 900, 1800, 3600)
DIMENSION_INDEX = {"channel": 3, "region": 4, "product": 5}
HISTORY_SECS = 7205
RETENTION_SECS = 7260


def portfolio_query(value):
    """Validate the full source contract, independently of gateway policy."""
    if (not isinstance(value, dict) or not {"view", "window_secs", "measures"} <= set(value)
            or not set(value) <= {"view", "window_secs", "measures", "dimension", "filters"}):
        raise ValueError("portfolio query shape")
    view, window, measures = value["view"], value["window_secs"], value["measures"]
    if (view not in ("summary", "trend", "breakdown", "comparison") or type(window) is not int
            or window not in PORTFOLIO_WINDOWS or not isinstance(measures, list)
            or not 1 <= len(measures) <= 4
            or any(not isinstance(m, str) or m not in PORTFOLIO_MEASURES for m in measures)
            or len(set(measures)) != len(measures)):
        raise ValueError("portfolio query scope")
    if view == "breakdown":
        if not isinstance(value.get("dimension"), str) or value["dimension"] not in PORTFOLIO_DIMENSIONS:
            raise ValueError("portfolio dimension")
    elif "dimension" in value:
        raise ValueError("dimension requires breakdown")
    filters = value.get("filters", {})
    if (not isinstance(filters, dict) or not set(filters) <= set(PORTFOLIO_DIMENSIONS)
            or any(not isinstance(v, str) or v not in PORTFOLIO_DIMENSIONS[k] for k, v in filters.items())):
        raise ValueError("portfolio filters")
    return value


class CreditSource(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, tenant, credential, directory, *, clock=time.time, produce=True, seed_history=None):
        self.tenant, self.credential = tenant, credential
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.clock, self.started_at = clock, clock()
        self.events, self.lock, self.stop = deque(), threading.Lock(), threading.Event()
        self.sequence = self.generated = self.queries = self.denied = 0
        self.seed = int.from_bytes(hashlib.sha256(tenant.encode()).digest()[:8], "big")
        self.random = random.Random(self.seed)
        self.history_start = self.started_at
        if seed_history if seed_history is not None else produce:
            self.history_start = self.started_at - HISTORY_SECS
            for tick in range(HISTORY_SECS * 2 + 1):
                self._tick_locked(self.history_start + tick / 2)
        super().__init__(("127.0.0.1", port), CreditHandler)
        if produce:
            threading.Thread(target=self.produce, daemon=True).start()

    def tick(self):
        now = self.clock()
        with self.lock:
            self._tick_locked(now)

    def _tick_locked(self, now):
        self.sequence += 1
        phase = (int(now // 120) + self.seed) % 4
        for _ in range((3, 5, 7, 4)[phase] + self.sequence % 3):
            self.generated += 1
            channel = self.random.choices(PORTFOLIO_DIMENSIONS["channel"], weights=(65, 25, 10))[0]
            region = self.random.choice(PORTFOLIO_DIMENSIONS["region"])
            product = self.random.choice(PORTFOLIO_DIMENSIONS["product"])
            # Two deliberately seeded operational patterns invite investigation.
            # These are correlations in fictional data, not causal explanations.
            mismatch_chance = .025 + (.16 if channel == "mobile" and now >= self.started_at - 900 else 0)
            mismatch = self.random.random() < mismatch_chance
            review_chance = .10 + (.10 if region == "west" else 0) + (.06 if product == "auto_loan" else 0)
            review = mismatch or self.random.random() < review_chance
            processing_ms = self.random.randint(300, 1800) + (900 if review else 0)
            if channel == "partner" and now >= self.started_at - 600:
                processing_ms += 2400
            self.events.append((now, review, mismatch, channel, region, product, processing_ms))
        while self.events and self.events[0][0] < now - RETENTION_SECS:
            self.events.popleft()

    def produce(self):
        while not self.stop.is_set():
            self.tick()
            self.stop.wait(.5)

    def aggregate(self, names, window):
        now = self.clock()
        with self.lock:
            events = [row for row in self.events if row[0] >= now - window]
            count = len(events)
            values = {
                "credit_applications_per_minute": count * 60 / window,
                "manual_review_rate_percent": 100 * sum(row[1] for row in events) / count if count else 0,
                "identity_mismatch_rate_percent": 100 * sum(row[2] for row in events) / count if count else 0,
            }
            self.queries += 1
            result = {"tenant_id": self.tenant, "window_secs": window, "as_of": int(now),
                      "watermark": int(events[-1][0]) if events else 0,
                      "metrics": [{"name": name, "value": values[name], "count": count} for name in names]}
            evidence = {"scenario": "credit_portfolio", "tenant_id": self.tenant,
                        "generated_events": self.generated, "aggregate_queries": self.queries,
                        "denied_requests": self.denied, "last_as_of": result["as_of"],
                        "last_watermark": result["watermark"], "last_window_secs": window,
                        "source_started_at": int(self.started_at),
                        "window_coverage_secs": min(window, max(0, int(now - self.history_start))),
                        "window_partial": now - self.history_start < window,
                        "last_metric_names": names, "raw_rows_exposed": False,
                        "borrower_records_present": False, "credit_decisions_enabled": False}
            (self.directory / "source-evidence.json").write_text(json.dumps(evidence))
            with (self.directory / "queries.jsonl").open("a") as output:
                output.write(json.dumps({"query": self.queries, "as_of": result["as_of"],
                                         "watermark": result["watermark"], "window_secs": window,
                                         "metrics": names, "sample_count": count}) + "\n")
            return result

    @staticmethod
    def portfolio_row(key, start, end, events, measures):
        samples = [row for row in events if start < row[0] <= end]
        count = len(samples)
        values = {"application_count": count,
                  "manual_review_count": sum(row[1] for row in samples),
                  "identity_mismatch_count": sum(row[2] for row in samples),
                  "manual_review_rate_percent": 100 * sum(row[1] for row in samples) / count if count else None,
                  "identity_mismatch_rate_percent": 100 * sum(row[2] for row in samples) / count if count else None,
                  "mean_processing_seconds": sum(row[6] for row in samples) / (1000 * count) if count else None}
        return {"key": key, "period_start": start, "period_end": end, "sample_count": count,
                "values": {m: values[m] for m in measures}}

    def portfolio(self, query):
        query = portfolio_query(query)
        now, window = int(self.clock()), query["window_secs"]
        earliest = now - window * (2 if query["view"] == "comparison" else 1)
        with self.lock:
            history_start = max(int(self.history_start), now - RETENTION_SECS)
            if earliest < history_start:
                raise ValueError("history unavailable")
            generated = [row for row in self.events if row[0] <= now]
            watermark = int(generated[-1][0]) if generated else 0
            samples = [row for row in generated if row[0] > earliest and len(row) == 7
                       and all(row[DIMENSION_INDEX[k]] == v for k, v in query.get("filters", {}).items())]
            measures = query["measures"]
            row = lambda key, start, end, data=samples: self.portfolio_row(key, start, end, data, measures)
            if query["view"] == "trend":
                width = window // 6
                rows = [row("bucket_" + str(i), now - window + i * width, now - window + (i + 1) * width)
                        for i in range(6)]
            elif query["view"] == "breakdown":
                dimension = query["dimension"]
                rows = [row(key, now - window, now, [r for r in samples if r[DIMENSION_INDEX[dimension]] == key])
                        for key in PORTFOLIO_DIMENSIONS[dimension]]
            elif query["view"] == "comparison":
                rows = [row("current", now - window, now), row("previous", now - 2 * window, now - window)]
            else:
                rows = [row("all", now - window, now)]
            comparisons = []
            if query["view"] == "comparison":
                for measure in measures:
                    current, previous = rows[0]["values"][measure], rows[1]["values"][measure]
                    delta = current - previous if current is not None and previous is not None else None
                    comparisons.append({"measure": measure, "current": current, "previous": previous,
                                        "delta": delta, "delta_unit": "applications" if measure.endswith("_count")
                                        else "seconds" if measure == "mean_processing_seconds" else "percentage_points",
                                        "relative_percent": delta / abs(previous) * 100 if delta is not None and previous else None})
            result = {"tenant_id": self.tenant, "query": query, "as_of": now, "watermark": watermark,
                      "history_start": history_start, "history_kind": "synthetic_seeded_and_live",
                      "rows": rows, "comparison": comparisons}
            self.queries += 1
            evidence = {"scenario": "credit_portfolio", "tenant_id": self.tenant, "generated_events": self.generated,
                        "aggregate_queries": self.queries, "denied_requests": self.denied,
                        "last_as_of": now, "last_watermark": watermark, "last_window_secs": window,
                        "source_started_at": int(self.started_at), "history_start": history_start,
                        "window_coverage_secs": window, "window_partial": False, "last_portfolio_query": query,
                        "returned_rows": len(rows), "raw_rows_exposed": False,
                        "borrower_records_present": False, "credit_decisions_enabled": False}
            (self.directory / "source-evidence.json").write_text(json.dumps(evidence))
            with (self.directory / "queries.jsonl").open("a") as output:
                output.write(json.dumps({"query": self.queries, "as_of": now, "portfolio": query,
                                         "sample_count": sum(r["sample_count"] for r in rows)}) + "\n")
            return result

    def shutdown(self):
        self.stop.set()
        super().shutdown()


class CreditHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        values = self.headers.get_all("Authorization", [])
        return len(values) == 1 and hmac.compare_digest(values[0], "Bearer " + self.server.credential)

    def do_GET(self):
        if not self.authorized():
            return self.reply(401, {"error": "source_credential_required"})
        if self.path == "/health":
            return self.reply(200, {"status": "ok", "source": "synthetic loan application events"})
        self.reply(404, {"error": "unsupported_source_route"})

    def do_POST(self):
        if not self.authorized():
            with self.server.lock:
                self.server.denied += 1
            return self.reply(401, {"error": "source_credential_required"})
        if self.path not in ("/v1/metrics/query", "/v1/portfolio/query"):
            return self.reply(404, {"error": "unsupported_source_route"})
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                raise ValueError("framing")
            length = int(lengths[0])
            if not 0 < length <= 4096:
                raise ValueError("size")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("truncated")
            value = json.loads(body)
            if self.path == "/v1/portfolio/query":
                return self.reply(200, self.server.portfolio(value))
            if not isinstance(value, dict) or set(value) != {"metrics", "window_secs"}:
                raise ValueError("shape")
            names, window = value["metrics"], value["window_secs"]
            if (not isinstance(names, list) or not 1 <= len(names) <= len(ALLOWED_METRICS)
                    or not all(isinstance(name, str) and name in ALLOWED_METRICS for name in names)
                    or len(set(names)) != len(names) or type(window) is not int or not 1 <= window <= 300):
                raise ValueError("scope")
        except (ValueError, TypeError):
            with self.server.lock:
                self.server.denied += 1
            return self.reply(400, {"error": "bounded_portfolio_aggregates_only"})
        self.reply(200, self.server.aggregate(names, window))
