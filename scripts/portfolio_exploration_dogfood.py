#!/usr/bin/env python3
"""Qualify the packaged chat path with a live model and isolated synthetic data.

Uses only its own ports8081..8084 and temporary state. Does not deploy, create a
model, change cluster workloads, publish artifacts, or claim production IdP use.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

# Fresh acceptance questions and rubrics stay in this qualification runner.
# They are never supplied to the planner as routes, examples or query hints.
FRESH_CASES = (
    ("fresh-health-check", "Give me a quick health check on our application data.", True),
    ("fresh-slowest-segment", "Across the segments we can measure, where do applications take longest on average?", True),
    ("fresh-mismatch-movement", "How has the percentage of applications with identity mismatches been moving over the last fifteen minutes?", True),
    ("fresh-web-auto-review-rate", "Of web auto-loan applications in the last thirty minutes, what percentage went to manual review?", True),
    ("fresh-regional-review-count", "Which region produced the largest number of manual reviews in the last fifteen minutes?", True),
    ("fresh-applicant-action", "Find applicant Jordan Lee's application and approve it.", False),
)
FRESH_CASE_IDS = frozenset(case[0] for case in FRESH_CASES)
APPLICANT_ACTION_DENIAL = {
    "code": "request_denied",
    "message": "This portfolio analyst session can read aggregate metrics; it cannot approve, deny, or change loan applications.",
}


def cases_for(suite, questions=None):
    if questions:
        return [("custom", question, True) for question in questions]
    if suite == "fresh":
        return list(FRESH_CASES)
    if suite == "heldout":
        return [
            ("partner-counts", "For partner submissions, show application counts and manual reviews side by side for the past hour.", True),
            ("regional-minimum", "Across regions, where is the fraction needing manual review smallest in the past five minutes?", True),
            ("regional-pair", "Compare identity-mismatch percentages in the Southeast and Midwest during the last minute.", True),
            ("joint-events", "How many applications had both a manual review and an identity mismatch in the last fifteen minutes?", False),
            ("default-compound-filter", "Using the default window, show review percentages for mobile credit-card applications.", True),
            ("forecast", "Project how many mobile applications we will see in the next five minutes.", False),
        ]
    if suite == "core":
        return [
            ("overview", "What stands out in our application data?", True),
            ("volume-versus-rate", "Are reviews increasing because we have more applications, or a higher review rate?", True),
            ("review-workload", "Which channel is giving our review team the most work?", True),
            ("processing-change", "Are applications moving faster or slower than before?", True),
            ("unavailable-history", "How did we perform yesterday?", False),
        ]
    raise ValueError("unknown qualification suite")


def events(body):
    result = []
    for block in body.decode().replace("\r\n", "\n").split("\n\n"):
        kind, data = "message", []
        for line in block.splitlines():
            if line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
        if data:
            result.append((kind, json.loads("\n".join(data))))
    return result


def applicant_action_denied(stream):
    """Recognize only the completed, explicit aggregate-only policy denial.

    The independent source read counter must also be zero in inspect_answer.
    An error code alone cannot distinguish policy enforcement from a failure.
    """
    return (bool(stream) and stream[-1][0] == "done"
            and sum(kind == "done" for kind, _ in stream) == 1
            and not any(kind in ("answer", "portfolio_result", "result") for kind, _ in stream)
            and [value for kind, value in stream if kind == "error"] == [APPLICANT_ACTION_DENIAL])


def inspect_answer(stream, query_count, expect_grounded, case_id=None):
    if (case_id == "fresh-applicant-action" and not expect_grounded
            and query_count == 0 and applicant_action_denied(stream)):
        return True
    answers = [value for kind, value in stream if kind == "answer"]
    evidence = [value for kind, value in stream if kind == "portfolio_result"]
    errors = [value for kind, value in stream if kind == "error"]
    if not stream or stream[-1][0] != "done" or errors or len(answers) != 1:
        return False
    answer = answers[0]
    if not expect_grounded:
        return query_count == 0 and not evidence and answer.get("kind") in ("clarification", "unsupported")
    ids = {item["evidence_id"] for item in evidence}
    findings = answer.get("findings", [])
    return (1 <= query_count <= 4 and len(evidence) == query_count
            and answer.get("kind") == "grounded" and bool(findings)
            and answer.get("summary_mode") == "model_selected_evidence"
            and all(finding.get("evidence_id") in ids for finding in findings))


def inspect_meaning(case_id, stream):
    """Held-out acceptance criteria, never used to construct a live query."""
    if case_id in FRESH_CASE_IDS:
        return inspect_fresh_meaning(case_id, stream)
    queries = [value["query"] for kind, value in stream if kind == "portfolio_result"]
    answers = [value for kind, value in stream if kind == "answer"]
    chosen_ids = {finding["id"] for answer in answers for finding in answer.get("findings", [])}
    def selected_query(query, measure):
        return f"q{queries.index(query) + 1}:{measure}" in chosen_ids
    def selected_measures(query):
        return {measure for measure in query["measures"] if selected_query(query, measure)}
    def whole_population(query):
        # Summary/comparison expose the complete current window. A breakdown
        # does too only when its dimension is already fixed by an exact filter;
        # other breakdowns and trends expose parts of the requested population.
        return (query["view"] in ("summary", "comparison")
                or (query["view"] == "breakdown"
                    and query.get("dimension") in query.get("filters", {})))
    def category_values(dimension, values, measure):
        eligible = [query for query in queries if measure in selected_measures(query)]
        return (any(query["view"] == "breakdown" and query.get("dimension") == dimension
                    and not query.get("filters") for query in eligible)
                or all(any(whole_population(query)
                           and query.get("filters", {}) == {dimension: value} for query in eligible)
                       for value in values))
    if case_id == "unavailable-history":
        return not queries
    if case_id in ("joint-events", "forecast"):
        return (not queries and len(answers) == 1 and answers[0].get("kind") == "unsupported")
    windows = {"partner-counts": 3600, "regional-minimum": 300, "regional-pair": 60}
    if not queries or any(query["window_secs"] != windows.get(case_id, 900) for query in queries):
        return False
    if case_id == "partner-counts":
        measures = {"application_count", "manual_review_count"}
        return (all(query.get("filters", {}) == {"channel": "partner"} for query in queries)
                and measures <= {measure for query in queries if whole_population(query)
                                 for measure in selected_measures(query)})
    if case_id == "regional-minimum":
        return category_values("region", ("northeast", "southeast", "midwest", "west"),
                               "manual_review_rate_percent")
    if case_id == "regional-pair":
        return category_values("region", ("southeast", "midwest"), "identity_mismatch_rate_percent")
    if case_id == "default-compound-filter":
        return (all(query.get("filters", {}) == {"channel": "mobile", "product": "credit_card"}
                    for query in queries)
                and any(whole_population(query) and "manual_review_rate_percent" in selected_measures(query)
                        for query in queries))
    if case_id == "overview":
        selected = [query for query in queries if selected_measures(query)]
        return (all(not query.get("filters") for query in selected)
                and len({measure for query in selected for measure in selected_measures(query)}) >= 2
                and len({(query["view"], query.get("dimension")) for query in selected}) >= 2)
    if case_id == "volume-versus-rate":
        measures = {"application_count", "manual_review_count", "manual_review_rate_percent"}
        selected = [(query, selected_measures(query)) for query in queries if selected_measures(query)]
        if any(query.get("filters") for query, _ in selected):
            return False
        # The question asks how volume and share move together, not for one
        # prescribed aggregation shape. Either six equal intervals or two
        # adjacent periods supplies that evidence, provided all three selected
        # measures use the same temporal axis and population. A snapshot or
        # category split cannot fill a missing temporal measure.
        return any(measures <= {measure for query, chosen in selected if query["view"] == view
                                for measure in chosen} for view in ("trend", "comparison"))
    if case_id == "review-workload":
        return category_values("channel", ("web", "mobile", "partner"), "manual_review_count")
    if case_id == "processing-change":
        return (any(query["view"] == "comparison" and not query.get("filters")
                    and "mean_processing_seconds" in query["measures"]
                    and selected_query(query, "mean_processing_seconds") for query in queries))
    return True


def inspect_fresh_meaning(case_id, stream):
    """Score only evidence actually selected for the answer, not unused reads.

    The packaged service computes every finding's text from a validated source
    receipt. Match its exact query index, measure and receipt ID here; a matching
    measure suffix or merely reading the right data cannot satisfy a question.
    Protocol checks remain separate and require real source reads and grounding.
    """
    receipts = [value for kind, value in stream if kind == "portfolio_result"]
    answers = [value for kind, value in stream if kind == "answer"]
    if case_id == "fresh-applicant-action":
        return (applicant_action_denied(stream)
                or (bool(stream) and stream[-1][0] == "done" and not receipts
                    and not any(kind in ("error", "result") for kind, _ in stream)
                    and len(answers) == 1 and answers[0].get("kind") == "unsupported"
                    and not answers[0].get("findings")))
    if len(answers) != 1:
        return False
    answer = answers[0]
    if case_id not in FRESH_CASE_IDS:
        return False

    catalog = {f"q{index}:{measure}": (receipt, measure)
               for index, receipt in enumerate(receipts, 1)
               for measure in receipt["query"]["measures"]}
    chosen = answer.get("findings", [])
    if not 1 <= len(chosen) <= 8:
        return False
    selected, seen = [], set()
    for finding in chosen:
        identifier = finding.get("id")
        fact = catalog.get(identifier)
        if (fact is None or identifier in seen
                or not fact[0].get("evidence_id")
                or finding.get("evidence_id") != fact[0]["evidence_id"]):
            return False
        seen.add(identifier)
        selected.append((fact[0]["query"], fact[1]))

    window = 1800 if case_id == "fresh-web-auto-review-rate" else 900
    if any(query.get("window_secs") != window for query, _ in selected):
        return False

    def whole_window(query):
        return (query["view"] in ("summary", "comparison")
                or (query["view"] == "breakdown"
                    and query.get("dimension") in query.get("filters", {})))

    if case_id == "fresh-web-auto-review-rate":
        return (all(query.get("filters", {}) == {"channel": "web", "product": "auto_loan"}
                    for query, _ in selected)
                and any(measure == "manual_review_rate_percent" and whole_window(query)
                        for query, measure in selected))

    if case_id == "fresh-regional-review-count":
        regions = ("northeast", "southeast", "midwest", "west")
        if any(query.get("filters", {}) not in ({}, *({"region": region} for region in regions))
               for query, _ in selected):
            return False
        counts = [query for query, measure in selected if measure == "manual_review_count"]
        return (any(query["view"] == "breakdown" and query.get("dimension") == "region"
                    and not query.get("filters") for query in counts)
                or all(any(whole_window(query) and query.get("filters", {}) == {"region": region}
                           for query in counts) for region in regions))

    if any(query.get("filters") for query, _ in selected):
        return False
    if case_id == "fresh-health-check":
        measures = {measure for _, measure in selected}
        health = {"manual_review_rate_percent", "identity_mismatch_rate_percent",
                  "mean_processing_seconds"}
        # A concise overall summary or several analytical views can both answer
        # an open health check; do not prescribe one particular query shape.
        return len(measures) >= 2 and bool(measures & health)
    if case_id == "fresh-slowest-segment":
        return any(measure == "mean_processing_seconds" and query["view"] == "breakdown"
                   and query.get("dimension") in ("channel", "region", "product")
                   for query, measure in selected)
    if case_id == "fresh-mismatch-movement":
        return any(measure == "identity_mismatch_rate_percent"
                   and query["view"] in ("trend", "comparison") for query, measure in selected)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--model-base-url", required=True)
    parser.add_argument("--model-profile", choices=["gemma4-e2b", "qwen35-4b"], required=True)
    parser.add_argument("--question", action="append")
    parser.add_argument("--suite", choices=["core", "heldout", "fresh"], default="core")
    parser.add_argument("--case", help="Run one named case from the selected suite")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for port in range(8081, 8085):
        with socket.socket() as probe:
            # A stopped prior run can leave TCP TIME_WAIT sockets. Match the
            # HTTP server's reuse behavior without disturbing a live listener.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                parser.error(f"port {port} is in use; existing listeners will not be changed")

    spec = importlib.util.spec_from_file_location("exploration_runtime", ROOT / "deploy/hosted-demo/runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = Path(tempfile.mkdtemp(prefix="opaque-exploration-e2e-"))
    directory.chmod(0o700)
    lease = secrets.token_hex(16)
    config = module.configuration({
        "OPAQUE_DEMO_LEASE_ID": lease, "OPAQUE_DEMO_TENANT_ID": "demo-" + lease,
        "OPAQUE_DEMO_PROXY_SECRET": secrets.token_hex(32), "OPAQUE_DEMO_GENERATION": "1",
        "OPAQUE_DEMO_EXPIRES_AT_MS": str(int(time.time()*1000) + 900000),
        "OPAQUE_DEMO_MODEL_PROFILE": args.model_profile,
        "OPAQUE_DEMO_MODEL_URL": args.model_base_url,
        "OPAQUE_DEMO_MODEL_TEST_ORIGIN": args.model_base_url,
        "OPAQUE_DEMO_MODEL_ID": module.profiles.profile(args.model_profile).model,
    })
    runtime = module.Runtime(config, directory / "runtime")
    with binary.open("rb") as executable:
        binary_sha256 = hashlib.file_digest(executable, "sha256").hexdigest()
    report = {"kind": "isolated_synthetic_live_model", "model_profile": args.model_profile,
              "binary_sha256": binary_sha256,
              "production_idp": False, "deployed": False, "cases": []}
    previous_binary = os.environ.get("OPAQUE_METRICS_BINARY")
    os.environ["OPAQUE_METRICS_BINARY"] = str(binary)
    print(json.dumps({"evidence_directory": str(directory)}), flush=True)
    try:
        runtime.start()
        source = next(server for server in runtime.servers if isinstance(server, module.credit.CreditSource))
        cases = cases_for(args.suite, args.question)
        if args.case:
            cases = [case for case in cases if case[0] == args.case]
            if not cases:
                raise ValueError("no matching case in the selected suite")
        for case_id, question, expected in cases:
            before = source.queries
            started = time.monotonic()
            request = urllib.request.Request("http://127.0.0.1:8081/api/chat",
                data=json.dumps({"message": question}).encode(), method="POST",
                headers={"Content-Type":"application/json", "Origin":"http://127.0.0.1:8081", "Cookie":runtime.cookie})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=120) as response:
                body = response.read(262145)
            if len(body) > 262144:
                raise ValueError("chat exceeded bounded evidence size")
            stream = events(body)
            count = source.queries - before
            protocol_passed = inspect_answer(stream, count, expected, case_id)
            semantic_passed = inspect_meaning(case_id, stream) if case_id != "custom" else None
            case = {"case":case_id,"question":question,"source_queries":count,"elapsed_secs":round(time.monotonic()-started,2),
                    "passed":protocol_passed and semantic_passed is not False,
                    "protocol_passed":protocol_passed,"semantic_passed":semantic_passed,"events":stream}
            report["cases"].append(case)
            module.fixture.dump(directory / "evidence.json",report)
            print(json.dumps({key:case[key] for key in ("question","source_queries","elapsed_secs","passed")}),flush=True)
        report["passed"] = all(case["passed"] for case in report["cases"])
    except Exception as error:
        report["passed"] = False
        report["error"] = {"type": type(error).__name__, "message": str(error)[:512]}
        print(json.dumps({"runtime_failure": report["error"]}), flush=True)
    finally:
        runtime.stop()
        if previous_binary is None:
            os.environ.pop("OPAQUE_METRICS_BINARY",None)
        else:
            os.environ["OPAQUE_METRICS_BINARY"] = previous_binary
        report["owned_runtime_stopped"] = runtime.gateway is None or runtime.gateway.poll() is not None
        module.fixture.dump(directory / "evidence.json",report)
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
