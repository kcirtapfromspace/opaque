"""Offline regressions for held-out semantic scoring; no runtime or model IO."""
import copy
import unittest

import portfolio_exploration_dogfood as dogfood


MEASURE = "manual_review_rate_percent"
REGIONS = ("northeast", "southeast", "midwest", "west")


def regional_queries(view="summary"):
    return [{"view": view, "window_secs": 300, "measures": [MEASURE],
             "filters": {"region": region}} for region in REGIONS]


def stream_for(queries, selected=None, selected_ids=None):
    if selected is None:
        selected = range(1, len(queries) + 1)
    if selected_ids is None:
        selected_ids = [f"q{index}:{measure}" for index in selected
                        for measure in queries[index - 1]["measures"]]
    return ([('portfolio_result', {"query": query, "evidence_id": f"e{index}"})
             for index, query in enumerate(queries, 1)]
            + [('answer', {"findings": [{"id": identifier,
                                         "evidence_id": f"e{identifier.split(':', 1)[0][1:]}"}
                                        for identifier in selected_ids]})])


class RegionalMinimumMeaningTests(unittest.TestCase):
    def inspect(self, queries, selected=None):
        return dogfood.inspect_meaning("regional-minimum", stream_for(queries, selected))

    def test_region_breakdown_and_all_selected_regional_totals_are_equivalent(self):
        self.assertTrue(self.inspect([{"view": "breakdown", "window_secs": 300,
                                      "dimension": "region", "measures": [MEASURE]}]))
        for view in ("summary", "comparison"):
            with self.subTest(view=view):
                self.assertTrue(self.inspect(regional_queries(view)))

    def test_all_regions_must_be_queried_and_selected(self):
        self.assertFalse(self.inspect(regional_queries()[:-1]))
        self.assertFalse(self.inspect(regional_queries(), selected=[1, 2, 3]))
        duplicate = regional_queries()
        duplicate[-1] = copy.deepcopy(duplicate[0])
        self.assertFalse(self.inspect(duplicate))

    def test_one_minute_or_mixed_windows_cannot_answer_five_minutes(self):
        for changed in (range(4), [3]):
            with self.subTest(changed=list(changed)):
                queries = regional_queries()
                for index in changed:
                    queries[index]["window_secs"] = 60
                self.assertFalse(self.inspect(queries))

    def test_extra_filters_or_wrong_measure_change_the_requested_population(self):
        for field in ("filter", "measure"):
            with self.subTest(field=field):
                queries = regional_queries()
                if field == "filter":
                    queries[0]["filters"]["channel"] = "web"
                else:
                    queries[0]["measures"] = ["manual_review_count"]
                self.assertFalse(self.inspect(queries))

    def test_trend_bucket_rates_do_not_supply_whole_window_regional_rates(self):
        self.assertFalse(self.inspect(regional_queries("trend")))


class FocusedWholeWindowMeaningTests(unittest.TestCase):
    def cases(self):
        return [
            ("partner-counts", [{"view": "summary", "window_secs": 3600,
                                 "measures": ["application_count", "manual_review_count"],
                                 "filters": {"channel": "partner"}}]),
            ("regional-pair", [{"view": "summary", "window_secs": 60,
                                "measures": ["identity_mismatch_rate_percent"],
                                "filters": {"region": region}} for region in ("southeast", "midwest")]),
            ("default-compound-filter", [{"view": "summary", "window_secs": 900,
                                          "measures": [MEASURE],
                                          "filters": {"channel": "mobile", "product": "credit_card"}}]),
        ]

    def test_whole_window_alternatives_pass_but_trend_only_substitutes_fail(self):
        for case, original in self.cases():
            for view, expected in (("summary", True), ("comparison", True), ("trend", False)):
                with self.subTest(case=case, view=view):
                    queries = copy.deepcopy(original)
                    for query in queries:
                        query["view"] = view
                    self.assertEqual(dogfood.inspect_meaning(case, stream_for(queries)), expected)

    def test_breakdown_is_equivalent_only_when_its_dimension_is_fixed(self):
        for case, original in self.cases():
            for fixed_dimension in (True, False):
                with self.subTest(case=case, fixed_dimension=fixed_dimension):
                    queries = copy.deepcopy(original)
                    for query in queries:
                        query["view"] = "breakdown"
                        query["dimension"] = (next(iter(query["filters"])) if fixed_dimension else
                                              next(d for d in ("region", "channel", "product")
                                                   if d not in query["filters"]))
                    self.assertEqual(dogfood.inspect_meaning(case, stream_for(queries)), fixed_dimension)
        region_breakdown = [{"view": "breakdown", "dimension": "region", "window_secs": 60,
                             "measures": ["identity_mismatch_rate_percent"]}]
        self.assertTrue(dogfood.inspect_meaning("regional-pair", stream_for(region_breakdown)))

    def test_every_required_fact_must_be_selected_from_a_whole_window_query(self):
        for case, original in self.cases():
            with self.subTest(case=case):
                queries = copy.deepcopy(original)
                for query in queries:
                    query["view"] = "trend"
                queries.extend(copy.deepcopy(original))
                # Merely reading the correct query cannot rescue selecting only
                # the trend facts; nor can an ID with the right measure suffix.
                self.assertFalse(dogfood.inspect_meaning(case, stream_for(queries, selected=range(1, len(original) + 1))))
                self.assertFalse(dogfood.inspect_meaning(case, stream_for(original, selected_ids=[
                    f"q99:{measure}" for query in original for measure in query["measures"]])))
                self.assertTrue(dogfood.inspect_meaning(case, stream_for(queries, selected=range(len(original) + 1, len(queries) + 1))))
        case, queries = self.cases()[0]
        for measure in queries[0]["measures"]:
            self.assertFalse(dogfood.inspect_meaning(case, stream_for(queries, selected_ids=[f"q1:{measure}"])))

    def test_wrong_windows_and_extra_filters_still_fail(self):
        for case, original in self.cases():
            for change in ("window", "filter"):
                with self.subTest(case=case, change=change):
                    queries = copy.deepcopy(original)
                    if change == "window":
                        queries[0]["window_secs"] = 300
                    else:
                        query = queries[0]
                        dimension = next(d for d in ("region", "channel", "product") if d not in query["filters"])
                        query["filters"][dimension] = {"region": "west", "channel": "web", "product": "auto_loan"}[dimension]
                    self.assertFalse(dogfood.inspect_meaning(case, stream_for(queries)))


class OverviewAndWorkloadMeaningTests(unittest.TestCase):
    def overview(self):
        return [{"view": "comparison", "window_secs": 900, "measures": [MEASURE]},
                {"view": "breakdown", "dimension": "channel", "window_secs": 900,
                 "measures": ["application_count"]}]

    def test_overview_requires_distinct_selected_unfiltered_views_and_measures(self):
        queries = self.overview()
        self.assertTrue(dogfood.inspect_meaning("overview", stream_for(queries)))
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(queries, selected=[1])))
        same_measure = self.overview()
        same_measure[1]["measures"] = [MEASURE]
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(same_measure)))
        same_view = self.overview()
        same_view[1]["view"] = "comparison"
        del same_view[1]["dimension"]
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(same_view)))

    def test_selected_filtered_facts_do_not_count_as_an_overview(self):
        for filtered in ([1], [0, 1]):
            queries = self.overview()
            for index in filtered:
                queries[index]["filters"] = {"region": "west"}
            self.assertFalse(dogfood.inspect_meaning("overview", stream_for(queries)))
        queries = self.overview()
        queries.append({"view": "summary", "window_secs": 900, "measures": [MEASURE],
                        "filters": {"region": "west"}})
        self.assertTrue(dogfood.inspect_meaning("overview", stream_for(queries, selected=[1, 2])))
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(queries)))

    def test_distinct_breakdown_dimensions_are_distinct_overview_perspectives(self):
        queries = [{"view": "breakdown", "dimension": "channel", "window_secs": 900,
                    "measures": ["manual_review_rate_percent"]},
                   {"view": "breakdown", "dimension": "product", "window_secs": 900,
                    "measures": ["mean_processing_seconds"]}]
        self.assertTrue(dogfood.inspect_meaning("overview", stream_for(queries)))
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(queries, selected=[1])))
        # Different measures alone do not create a second perspective when
        # both selected facts describe the same grouping.
        queries[1]["dimension"] = "channel"
        self.assertFalse(dogfood.inspect_meaning("overview", stream_for(queries)))

    def test_exhaustive_selected_channel_values_are_equivalent_to_breakdown(self):
        breakdown = [{"view": "breakdown", "dimension": "channel", "window_secs": 900,
                      "measures": ["manual_review_count"]}]
        self.assertTrue(dogfood.inspect_meaning("review-workload", stream_for(breakdown)))
        for view in ("summary", "comparison", "trend"):
            queries = [{"view": view, "window_secs": 900, "measures": ["manual_review_count"],
                        "filters": {"channel": channel}} for channel in ("web", "mobile", "partner")]
            self.assertEqual(dogfood.inspect_meaning("review-workload", stream_for(queries)), view != "trend")
            self.assertFalse(dogfood.inspect_meaning("review-workload", stream_for(queries[:-1])))
            self.assertFalse(dogfood.inspect_meaning("review-workload", stream_for(queries, selected=[1, 2])))
            queries[0]["filters"]["region"] = "west"
            self.assertFalse(dogfood.inspect_meaning("review-workload", stream_for(queries)))


class VolumeVersusRateMeaningTests(unittest.TestCase):
    measures = ("application_count", "manual_review_count", "manual_review_rate_percent")

    def queries(self, view="trend", split=False):
        groups = [self.measures[:2], self.measures[2:]] if split else [self.measures]
        return [{"view": view, "window_secs": 900, "measures": list(group)} for group in groups]

    def inspect(self, queries, **selection):
        return dogfood.inspect_meaning("volume-versus-rate", stream_for(queries, **selection))

    def test_all_three_selected_measures_can_share_trend_or_comparison(self):
        for view in ("trend", "comparison"):
            for split in (False, True):
                with self.subTest(view=view, split=split):
                    self.assertTrue(self.inspect(self.queries(view, split)))

    def test_snapshot_and_categorical_axes_do_not_show_increase(self):
        for view in ("summary", "breakdown"):
            queries = self.queries(view)
            if view == "breakdown":
                queries[0]["dimension"] = "channel"
            self.assertFalse(self.inspect(queries))

    def test_every_necessary_measure_must_be_selected_not_merely_read(self):
        for view in ("trend", "comparison"):
            for missing in self.measures:
                with self.subTest(view=view, missing=missing):
                    queries = self.queries(view)
                    chosen = [f"q1:{measure}" for measure in self.measures if measure != missing]
                    self.assertFalse(self.inspect(queries, selected_ids=chosen))
            self.assertFalse(self.inspect(self.queries(view, split=True), selected=[1]))
            self.assertFalse(self.inspect(self.queries(view, split=True), selected=[2]))

    def test_incompatible_temporal_axes_cannot_supply_a_missing_measure(self):
        for count_view in ("trend", "comparison"):
            for rate_view in ("trend", "comparison", "summary", "breakdown"):
                with self.subTest(count_view=count_view, rate_view=rate_view):
                    queries = self.queries(count_view, split=True)
                    queries[1]["view"] = rate_view
                    if rate_view == "breakdown":
                        queries[1]["dimension"] = "region"
                    self.assertEqual(self.inspect(queries), count_view == rate_view)

    def test_different_window_lengths_or_wrong_common_window_fail(self):
        for view in ("trend", "comparison"):
            for changed in ([0], [1], [0, 1]):
                with self.subTest(view=view, changed=changed):
                    queries = self.queries(view, split=True)
                    for index in changed:
                        queries[index]["window_secs"] = 300
                    self.assertFalse(self.inspect(queries))

    def test_filtered_or_mixed_cohorts_do_not_answer_global_question(self):
        for view in ("trend", "comparison"):
            for filters in ([{}, {"channel": "mobile"}],
                            [{"channel": "web"}, {"channel": "mobile"}],
                            [{"channel": "web"}, {"channel": "web"}]):
                with self.subTest(view=view, filters=filters):
                    queries = self.queries(view, split=True)
                    for query, cohort in zip(queries, filters):
                        query["filters"] = cohort
                    self.assertFalse(self.inspect(queries))

    def test_reading_temporal_evidence_cannot_rescue_selecting_only_snapshot_facts(self):
        for view in ("trend", "comparison"):
            queries = self.queries("summary") + self.queries(view)
            self.assertFalse(self.inspect(queries, selected=[1]))
            self.assertTrue(self.inspect(queries, selected=[2]))
            self.assertFalse(self.inspect(self.queries(view), selected_ids=[
                f"q99:{measure}" for measure in self.measures]))


class FreshMeaningTests(unittest.TestCase):
    def query(self, measure, view="summary", window=900, dimension=None, filters=None):
        result = {"view": view, "window_secs": window, "measures": [measure]}
        if dimension:
            result["dimension"] = dimension
        if filters:
            result["filters"] = filters
        return result

    def cases(self):
        return {
            "fresh-health-check": [dict(self.query("application_count"),
                                        measures=["application_count", MEASURE])],
            "fresh-slowest-segment": [self.query("mean_processing_seconds", "breakdown",
                                                dimension="product")],
            "fresh-mismatch-movement": [self.query("identity_mismatch_rate_percent", "trend")],
            "fresh-web-auto-review-rate": [self.query(MEASURE, window=1800,
                                                     filters={"channel": "web", "product": "auto_loan"})],
            "fresh-regional-review-count": [self.query("manual_review_count", "breakdown",
                                                      dimension="region")],
        }

    def inspect(self, case, queries, **selection):
        return dogfood.inspect_meaning(case, stream_for(queries, **selection))

    def test_suite_has_six_distinct_cases_and_one_unsupported_action(self):
        self.assertEqual(len(dogfood.FRESH_CASES), 6)
        self.assertEqual(len(dogfood.FRESH_CASE_IDS), 6)
        self.assertEqual({case for case, _, grounded in dogfood.FRESH_CASES if grounded},
                         set(self.cases()))
        self.assertEqual([case for case, _, grounded in dogfood.FRESH_CASES if not grounded],
                         ["fresh-applicant-action"])

    def test_suite_dispatch_preserves_core_heldout_and_custom_precedence(self):
        self.assertEqual([case[0] for case in dogfood.cases_for("core")],
                         ["overview", "volume-versus-rate", "review-workload",
                          "processing-change", "unavailable-history"])
        self.assertEqual([case[0] for case in dogfood.cases_for("heldout")],
                         ["partner-counts", "regional-minimum", "regional-pair",
                          "joint-events", "default-compound-filter", "forecast"])
        self.assertEqual(dogfood.cases_for("fresh"), list(dogfood.FRESH_CASES))
        for suite in ("core", "heldout", "fresh"):
            self.assertEqual(dogfood.cases_for(suite, ["first custom", "second custom"]),
                             [("custom", "first custom", True), ("custom", "second custom", True)])
        with self.assertRaises(ValueError):
            dogfood.cases_for("unknown")

    def test_canonical_selected_evidence_passes_all_grounded_cases(self):
        for case, queries in self.cases().items():
            with self.subTest(case=case):
                self.assertTrue(self.inspect(case, queries))

    def test_health_check_accepts_a_summary_or_multiple_views_but_needs_health_evidence(self):
        case = "fresh-health-check"
        queries = [self.query(MEASURE, "comparison"),
                   self.query("mean_processing_seconds", "breakdown", dimension="channel")]
        self.assertTrue(self.inspect(case, queries))
        self.assertFalse(self.inspect(case, queries, selected=[1]))
        counts_only = dict(self.query("application_count"),
                           measures=["application_count", "manual_review_count"])
        self.assertFalse(self.inspect(case, [counts_only]))

    def test_slowest_average_accepts_any_available_unfiltered_dimension(self):
        for dimension in ("channel", "region", "product"):
            with self.subTest(dimension=dimension):
                self.assertTrue(self.inspect("fresh-slowest-segment", [
                    self.query("mean_processing_seconds", "breakdown", dimension=dimension)]))
        for view in ("summary", "comparison", "trend"):
            self.assertFalse(self.inspect("fresh-slowest-segment", [
                self.query("mean_processing_seconds", view)]))
        self.assertFalse(self.inspect("fresh-slowest-segment", [
            self.query("application_count", "breakdown", dimension="product")]))

    def test_mismatch_movement_accepts_trend_or_comparison_but_requires_the_share(self):
        for view, expected in (("trend", True), ("comparison", True), ("summary", False)):
            with self.subTest(view=view):
                self.assertEqual(self.inspect("fresh-mismatch-movement", [
                    self.query("identity_mismatch_rate_percent", view)]), expected)
        for measure in ("identity_mismatch_count", MEASURE):
            self.assertFalse(self.inspect("fresh-mismatch-movement", [self.query(measure, "trend")]))

    def test_web_auto_percentage_needs_both_exact_filters_and_whole_window(self):
        case = "fresh-web-auto-review-rate"
        for view, expected in (("summary", True), ("comparison", True), ("trend", False)):
            self.assertEqual(self.inspect(case, [self.query(MEASURE, view, window=1800,
                filters={"channel": "web", "product": "auto_loan"})]), expected)
        for dimension, expected in (("channel", True), ("product", True), ("region", False)):
            self.assertEqual(self.inspect(case, [self.query(MEASURE, "breakdown", window=1800,
                dimension=dimension, filters={"channel": "web", "product": "auto_loan"})]), expected)
        for filters in ({"channel": "web"}, {"product": "auto_loan"},
                        {"channel": "mobile", "product": "auto_loan"},
                        {"channel": "web", "product": "personal_loan"},
                        {"channel": "web", "product": "auto_loan", "region": "west"}):
            with self.subTest(filters=filters):
                self.assertFalse(self.inspect(case, [self.query(MEASURE, window=1800, filters=filters)]))
        self.assertFalse(self.inspect(case, [self.query("manual_review_count", window=1800,
            filters={"channel": "web", "product": "auto_loan"})]))

    def test_regional_workload_needs_selected_counts_for_all_regions(self):
        case = "fresh-regional-review-count"
        for view in ("summary", "comparison"):
            queries = [self.query("manual_review_count", view, filters={"region": region})
                       for region in REGIONS]
            self.assertTrue(self.inspect(case, queries))
            self.assertFalse(self.inspect(case, queries[:-1]))
            self.assertFalse(self.inspect(case, queries, selected=[1, 2, 3]))
            queries[-1]["window_secs"] = 300
            self.assertFalse(self.inspect(case, queries))
        for measure, view, dimension in ((MEASURE, "breakdown", "region"),
                                         ("manual_review_count", "breakdown", "channel")):
            self.assertFalse(self.inspect(case, [self.query(measure, view, dimension=dimension)]))
        self.assertFalse(self.inspect(case, [self.query("manual_review_count", "trend",
            filters={"region": region}) for region in REGIONS]))

    def test_selected_wrong_windows_or_extra_filters_fail_every_grounded_case(self):
        for case, original in self.cases().items():
            for change in ("window", "filter"):
                with self.subTest(case=case, change=change):
                    queries = copy.deepcopy(original)
                    if change == "window":
                        queries[0]["window_secs"] = 60
                    else:
                        queries[0].setdefault("filters", {})["region"] = "west"
                    self.assertFalse(self.inspect(case, queries))

    def test_reading_correct_evidence_cannot_rescue_selecting_wrong_or_unrelated_facts(self):
        for case, original in self.cases().items():
            with self.subTest(case=case):
                wrong = copy.deepcopy(original)
                for query in wrong:
                    query["window_secs"] = 60
                queries = wrong + copy.deepcopy(original)
                self.assertFalse(self.inspect(case, queries, selected=[1]))
                # Unused exploratory reads do not invalidate a correct answer.
                self.assertTrue(self.inspect(case, queries, selected=[2]))
                self.assertFalse(self.inspect(case, queries))
                self.assertFalse(self.inspect(case, original, selected_ids=[
                    f"q99:{measure}" for measure in original[0]["measures"]]))

    def test_exact_receipts_and_unique_finding_ids_are_required(self):
        for case, queries in self.cases().items():
            with self.subTest(case=case):
                stream = stream_for(queries)
                stream[-1][1]["findings"][0]["evidence_id"] = "some-other-receipt"
                self.assertFalse(dogfood.inspect_meaning(case, stream))
                stream = stream_for(queries)
                stream[-1][1]["findings"].append(copy.deepcopy(stream[-1][1]["findings"][0]))
                self.assertFalse(dogfood.inspect_meaning(case, stream))
        # A receipt that exists elsewhere still cannot back the chosen query's
        # finding; the query index and measure must match that exact receipt.
        queries = [self.query("identity_mismatch_rate_percent", "trend"),
                   self.query("identity_mismatch_rate_percent", "summary")]
        stream = stream_for(queries, selected=[1])
        stream[-1][1]["findings"][0]["evidence_id"] = "e2"
        self.assertFalse(dogfood.inspect_meaning("fresh-mismatch-movement", stream))

    def test_individual_action_requires_an_explicit_unsupported_answer_without_reads(self):
        case = "fresh-applicant-action"
        stream = [("answer", {"kind": "unsupported"}), ("done", {})]
        self.assertTrue(dogfood.inspect_meaning(case, stream))
        self.assertTrue(dogfood.inspect_answer(stream, 0, False))
        self.assertFalse(dogfood.inspect_answer(stream, 1, False))
        for kind in ("clarification", "grounded"):
            self.assertFalse(dogfood.inspect_meaning(case, [("answer", {"kind": kind})]))
        queried = stream_for([self.query("application_count")])
        queried[-1] = ("answer", {"kind": "unsupported"})
        self.assertFalse(dogfood.inspect_meaning(case, queried))
        self.assertFalse(dogfood.inspect_meaning(case, stream + [("answer", {"kind": "unsupported"})]))

    def policy_denial(self):
        return [("error", copy.deepcopy(dogfood.APPLICANT_ACTION_DENIAL)), ("done", {})]

    def test_individual_action_accepts_exact_completed_policy_denial_with_zero_reads(self):
        stream = self.policy_denial()
        self.assertTrue(dogfood.inspect_meaning("fresh-applicant-action", stream))
        self.assertTrue(dogfood.inspect_answer(stream, 0, False, "fresh-applicant-action"))
        self.assertFalse(dogfood.inspect_answer(stream, 1, False, "fresh-applicant-action"))
        self.assertFalse(dogfood.inspect_answer(stream, 0, True, "fresh-applicant-action"))
        # This policy refusal cannot pass an unrelated data question or custom
        # question's existing protocol check just because it performed no reads.
        for case in (None, "custom", "unavailable-history", "forecast", "fresh-health-check"):
            self.assertFalse(dogfood.inspect_answer(stream, 0, False, case))

    def test_policy_denial_rejects_unrelated_errors_and_incomplete_streams(self):
        invalid = [[], self.policy_denial()[:-1], list(reversed(self.policy_denial())),
                   self.policy_denial() + [("progress", {})],
                   self.policy_denial() + [("done", {})]]
        for error in ({"code": "auth_expired", "message": dogfood.APPLICANT_ACTION_DENIAL["message"]},
                      {"code": "request_denied", "message": "The model request failed."},
                      {"code": "transport_failure", "message": "Connection reset"},
                      {"code": "request_denied"},
                      {"message": dogfood.APPLICANT_ACTION_DENIAL["message"]}):
            invalid.append([("error", error), ("done", {})])
        invalid.append(self.policy_denial()[:1] + self.policy_denial())
        invalid.append([("error", {"code": "transport_failure"})] + self.policy_denial())
        for stream in invalid:
            with self.subTest(stream=stream):
                self.assertFalse(dogfood.inspect_meaning("fresh-applicant-action", stream))
                self.assertFalse(dogfood.inspect_answer(stream, 0, False, "fresh-applicant-action"))

    def test_policy_denial_rejects_answers_or_evidence_even_with_correct_denial_text(self):
        additions = [("answer", {"kind": "unsupported"}),
                     ("answer", {"kind": "grounded", "findings": []}),
                     ("portfolio_result", {"query": self.query("application_count"),
                                           "evidence_id": "e1"}),
                     ("result", {"evidence_id": "e1"})]
        for addition in additions:
            with self.subTest(event=addition[0]):
                stream = [addition] + self.policy_denial()
                self.assertFalse(dogfood.inspect_meaning("fresh-applicant-action", stream))
                self.assertFalse(dogfood.inspect_answer(stream, 0, False, "fresh-applicant-action"))


if __name__ == "__main__":
    unittest.main()
