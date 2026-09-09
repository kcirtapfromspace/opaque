//! Language models select relevant findings; source-computed evidence supplies
//! every displayed fact. An unknown fact ID can never become an answer.
use crate::portfolio::{Dimension, PortfolioEvidence, PortfolioQuery, View, category_label};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub evidence_id: String,
    pub text: String,
}

/// Describe validated query structure, never the model's free-form account of
/// its plan. This text cannot introduce observations before a source is read.
pub fn plan_description(queries: &[PortfolioQuery]) -> String {
    queries
        .iter()
        .enumerate()
        .map(|(index, query)| {
            let measures = query
                .measures
                .iter()
                .map(|measure| format!("{} ({})", measure.label(), measure.unit()))
                .collect::<Vec<_>>()
                .join(", ");
            let window = format!(
                "{} minute{}",
                query.window_secs / 60,
                if query.window_secs == 60 { "" } else { "s" }
            );
            let operation = match query.view {
                View::Summary => format!("Summarize {measures} over the last {window}"),
                View::Trend => {
                    format!("Show {measures} across six equal intervals over the last {window}")
                }
                View::Comparison => {
                    format!("Compare {measures} for the last {window} with the preceding {window}")
                }
                View::Breakdown => format!(
                    "Compare {measures} by {} over the last {window}",
                    query
                        .dimension
                        .map(|dimension| dimension.id())
                        .unwrap_or("unspecified dimension")
                ),
            };
            let filters = [Dimension::Channel, Dimension::Region, Dimension::Product]
                .iter()
                .filter_map(|dimension| {
                    query
                        .filters
                        .get(*dimension)
                        .map(|value| format!("{}={}", dimension.id(), category_label(value)))
                })
                .collect::<Vec<_>>();
            format!(
                "{}. {operation}. {}.",
                index + 1,
                if filters.is_empty() {
                    "All permitted categories".into()
                } else {
                    format!("Filters: {}", filters.join(" AND "))
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each finding isolates one existing measure without recomputing or modifying
/// its source values. Interleave queries so a bounded fallback covers all reads.
pub fn findings(evidence: &[(String, PortfolioEvidence)]) -> Vec<Finding> {
    let mut groups = Vec::new();
    for (index, (id, original)) in evidence.iter().enumerate() {
        let mut group = Vec::new();
        for measure in &original.snapshot.query.measures {
            let mut selected = original.clone();
            selected.snapshot.query.measures = vec![*measure];
            selected
                .snapshot
                .comparison
                .retain(|c| c.measure == *measure);
            for row in &mut selected.snapshot.rows {
                row.values.retain(|key, _| key == measure);
            }
            group.push(Finding {
                id: format!("q{}:{}", index + 1, measure.id()),
                evidence_id: id.clone(),
                text: selected.answer().trim_end_matches(" Synthetic computed aggregates; these comparisons do not establish causes or individual credit decisions.").to_owned(),
            });
        }
        groups.push(group);
    }
    let mut result = Vec::new();
    for measure_index in 0..4 {
        for group in &groups {
            if let Some(finding) = group.get(measure_index) {
                result.push(finding.clone());
            }
        }
    }
    result
}

pub fn selected<'a>(catalog: &'a [Finding], ids: &[String]) -> Result<Vec<&'a Finding>, String> {
    if ids.is_empty() || ids.len() > 8 || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("The answer must select between one and eight distinct evidence facts.".into());
    }
    ids.iter()
        .map(|id| {
            catalog.iter().find(|fact| &fact.id == id).ok_or_else(|| {
                "The answer referenced a fact that was not in the validated evidence.".into()
            })
        })
        .collect()
}

pub fn answer(catalog: &[Finding], ids: &[String], fallback: bool) -> Result<String, String> {
    let facts = selected(catalog, ids)?;
    let intro = if fallback {
        "The evidence is available, but the model could not select a valid summary. Here are computed observations from the authorized data:"
    } else {
        "The authorized data shows:"
    };
    let observations = facts
        .iter()
        .enumerate()
        .map(|(index, fact)| format!("[{}] {}", index + 1, fact.text))
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok(format!(
        "{intro}\n\n{observations}\n\nThese are synthetic application aggregates. They describe the observed periods and segments; they do not establish causes or individual credit decisions. Each source table shows its own snapshot time."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portfolio::{
        Filters, Measure, PortfolioQuery, PortfolioRow, PortfolioSnapshot, View,
    };
    #[test]
    fn plan_description_preserves_views_units_windows_and_filter_intersection() {
        let queries = vec![
            PortfolioQuery {
                view: View::Summary,
                window_secs: 60,
                measures: vec![Measure::ManualReviewCount],
                dimension: None,
                filters: Filters {
                    channel: Some("web".into()),
                    region: Some("west".into()),
                    product: Some("auto_loan".into()),
                },
            },
            PortfolioQuery {
                view: View::Comparison,
                window_secs: 1800,
                measures: vec![Measure::ManualReviewRatePercent],
                dimension: None,
                filters: Filters::default(),
            },
            PortfolioQuery {
                view: View::Trend,
                window_secs: 300,
                measures: vec![Measure::IdentityMismatchRatePercent],
                dimension: None,
                filters: Filters::default(),
            },
            PortfolioQuery {
                view: View::Breakdown,
                window_secs: 900,
                measures: vec![Measure::MeanProcessingSeconds],
                dimension: Some(Dimension::Product),
                filters: Filters::default(),
            },
        ];
        let description = plan_description(&queries);
        assert!(description.contains("Manual reviews (applications) over the last 1 minute"));
        assert!(description.contains("channel=Web AND region=West AND product=Auto loan"));
        assert!(description.contains(
            "Manual review rate (%) for the last 30 minutes with the preceding 30 minutes"
        ));
        assert!(description.contains(
            "Identity mismatch rate (%) across six equal intervals over the last 5 minutes"
        ));
        assert!(
            description
                .contains("Mean processing time (seconds) by product over the last 15 minutes")
        );
        assert_eq!(description.lines().count(), 4);
        assert_eq!(description.matches("All permitted categories").count(), 3);
    }
    fn evidence() -> PortfolioEvidence {
        PortfolioEvidence {
            snapshot: PortfolioSnapshot {
                tenant_id: "synthetic-a".into(),
                query: PortfolioQuery {
                    view: View::Summary,
                    window_secs: 900,
                    measures: vec![Measure::ApplicationCount, Measure::ManualReviewCount],
                    dimension: None,
                    filters: Filters::default(),
                },
                as_of: 1800000000,
                watermark: 1800000000,
                history_start: 1799990000,
                history_kind: "synthetic_seeded_and_live".into(),
                rows: vec![PortfolioRow {
                    key: "all".into(),
                    period_start: 1799999100,
                    period_end: 1800000000,
                    sample_count: 100,
                    values: [
                        (Measure::ApplicationCount, Some(100.)),
                        (Measure::ManualReviewCount, Some(7.)),
                    ]
                    .into(),
                }],
                comparison: vec![],
            },
            source_id: "fixture".into(),
            observed_at: 1800000000,
            coverage: "complete".into(),
        }
    }
    #[test]
    fn breakdown_facts_keep_interior_values_ties_and_missing_values() {
        let mut source = evidence();
        source.snapshot.query.view = View::Breakdown;
        source.snapshot.query.dimension = Some(Dimension::Region);
        source.snapshot.query.measures = vec![Measure::ManualReviewRatePercent];
        source.snapshot.rows = [
            ("northeast", 30.0),
            ("southeast", 10.0),
            ("midwest", 20.0),
            ("west", 30.0),
        ]
        .into_iter()
        .map(|(key, rate)| PortfolioRow {
            key: key.into(),
            period_start: source.snapshot.as_of - 900,
            period_end: source.snapshot.as_of,
            sample_count: 100,
            values: [(Measure::ManualReviewRatePercent, Some(rate))].into(),
        })
        .collect();
        source
            .snapshot
            .validate(
                "synthetic-a",
                &source.snapshot.query,
                &Measure::ALL,
                source.observed_at,
                60,
            )
            .unwrap();
        let catalog = findings(&[("all-regions".into(), source.clone())]);
        assert_eq!(catalog.len(), 1);
        let text = &catalog[0].text;
        assert!(text.contains("Northeast and West share the highest manual review rate: 30.00 %"));
        assert!(text.contains("Southeast=10.00 %; Midwest=20.00 %"));
        assert!(text.contains("Northeast=30.00 %"));
        assert!(text.contains("West=30.00 %"));
        assert!(text.contains("Samples: Northeast 100; Southeast 100; Midwest 100; West 100"));
        source.snapshot.rows[0].sample_count = 0;
        source.snapshot.rows[0]
            .values
            .insert(Measure::ManualReviewRatePercent, None);
        source
            .snapshot
            .validate(
                "synthetic-a",
                &source.snapshot.query,
                &Measure::ALL,
                source.observed_at,
                60,
            )
            .unwrap();
        let catalog = findings(&[("one-region-empty".into(), source)]);
        assert!(
            catalog[0]
                .text
                .contains("Northeast=unavailable (no samples)")
        );
        assert!(!catalog[0].text.contains("Northeast=0.00 %"));
        assert!(
            catalog[0]
                .text
                .contains("Samples: Northeast 0; Southeast 100; Midwest 100; West 100")
        );
    }
    #[test]
    fn numeric_findings_retain_source_denominators_windows_and_ids() {
        let original = evidence();
        let catalog = findings(&[
            ("evidence-one".into(), original.clone()),
            ("evidence-two".into(), original),
        ]);
        assert_eq!(catalog.len(), 4);
        assert_eq!(catalog[0].evidence_id, "evidence-one");
        assert_eq!(catalog[1].evidence_id, "evidence-two");
        let review = &catalog[2];
        assert!(review.text.contains("7 applications"));
        assert!(review.text.contains("15 minutes"));
        assert!(review.text.contains("100"));
        assert!(!review.text.contains("7.00 %"));
        let answer = answer(&catalog, std::slice::from_ref(&review.id), false).unwrap();
        assert!(answer.contains("do not establish causes"));
        assert!(answer.contains("[1]"));
    }
    #[test]
    fn fabricated_or_repeated_facts_cannot_be_rendered() {
        let catalog = findings(&[("proof".into(), evidence())]);
        assert!(answer(&catalog, &[], false).is_err());
        assert!(answer(&catalog, &["invented:9999".into()], false).is_err());
        assert!(
            answer(
                &catalog,
                &[catalog[0].id.clone(), catalog[0].id.clone()],
                false
            )
            .is_err()
        );
        assert!(
            answer(&catalog, &[catalog[0].id.clone()], true)
                .unwrap()
                .contains("could not select a valid summary")
        );
    }
}
