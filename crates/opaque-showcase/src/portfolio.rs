//! Bounded portfolio analytics. The source computes aggregates; the gateway
//! validates their shape and renders numeric answers without model arithmetic.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const WINDOWS: [u32; 5] = [60, 300, 900, 1800, 3600];
pub const READ_SCOPE: &str = "portfolio:read";
pub const TOOL: &str = "opaque_portfolio_query";
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Measure {
    ApplicationCount,
    ManualReviewCount,
    IdentityMismatchCount,
    ManualReviewRatePercent,
    IdentityMismatchRatePercent,
    MeanProcessingSeconds,
}
impl Measure {
    pub const ALL: [Self; 6] = [
        Self::ApplicationCount,
        Self::ManualReviewCount,
        Self::IdentityMismatchCount,
        Self::ManualReviewRatePercent,
        Self::IdentityMismatchRatePercent,
        Self::MeanProcessingSeconds,
    ];
    pub fn id(self) -> &'static str {
        match self {
            Self::ApplicationCount => "application_count",
            Self::ManualReviewCount => "manual_review_count",
            Self::IdentityMismatchCount => "identity_mismatch_count",
            Self::ManualReviewRatePercent => "manual_review_rate_percent",
            Self::IdentityMismatchRatePercent => "identity_mismatch_rate_percent",
            Self::MeanProcessingSeconds => "mean_processing_seconds",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::ApplicationCount => "Applications",
            Self::ManualReviewCount => "Manual reviews",
            Self::IdentityMismatchCount => "Identity mismatches",
            Self::ManualReviewRatePercent => "Manual review rate",
            Self::IdentityMismatchRatePercent => "Identity mismatch rate",
            Self::MeanProcessingSeconds => "Mean processing time",
        }
    }
    pub fn unit(self) -> &'static str {
        match self {
            Self::ApplicationCount | Self::ManualReviewCount | Self::IdentityMismatchCount => {
                "applications"
            }
            Self::ManualReviewRatePercent | Self::IdentityMismatchRatePercent => "%",
            Self::MeanProcessingSeconds => "seconds",
        }
    }
    pub fn delta_unit(self) -> &'static str {
        if matches!(
            self,
            Self::ManualReviewRatePercent | Self::IdentityMismatchRatePercent
        ) {
            "percentage_points"
        } else {
            self.unit()
        }
    }
    pub fn is_count(self) -> bool {
        matches!(
            self,
            Self::ApplicationCount | Self::ManualReviewCount | Self::IdentityMismatchCount
        )
    }
    pub fn scope(self) -> String {
        format!("portfolio:measure:{}", self.id())
    }
    fn valid(self, value: f64) -> bool {
        value.is_finite()
            && value >= 0.0
            && match self {
                Self::ApplicationCount | Self::ManualReviewCount | Self::IdentityMismatchCount => {
                    value <= 1_000_000_000.0 && value.fract() == 0.0
                }
                Self::ManualReviewRatePercent | Self::IdentityMismatchRatePercent => value <= 100.0,
                Self::MeanProcessingSeconds => value <= 1_000_000.0,
            }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Summary,
    Trend,
    Breakdown,
    Comparison,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Channel,
    Region,
    Product,
}
impl Dimension {
    pub fn id(self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Region => "region",
            Self::Product => "product",
        }
    }
    pub fn values(self) -> &'static [&'static str] {
        match self {
            Self::Channel => &["web", "mobile", "partner"],
            Self::Region => &["northeast", "southeast", "midwest", "west"],
            Self::Product => &["personal_loan", "auto_loan", "credit_card"],
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}
impl Filters {
    pub fn get(&self, dimension: Dimension) -> Option<&str> {
        match dimension {
            Dimension::Channel => self.channel.as_deref(),
            Dimension::Region => self.region.as_deref(),
            Dimension::Product => self.product.as_deref(),
        }
    }
    fn empty(&self) -> bool {
        self.channel.is_none() && self.region.is_none() && self.product.is_none()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortfolioQuery {
    pub view: View,
    pub window_secs: u32,
    pub measures: Vec<Measure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<Dimension>,
    #[serde(default, skip_serializing_if = "Filters::empty")]
    pub filters: Filters,
}
impl PortfolioQuery {
    pub fn validate(&self, allowed: &[Measure]) -> Result<(), String> {
        if !WINDOWS.contains(&self.window_secs)
            || self.measures.is_empty()
            || self.measures.len() > 4
            || self.measures.iter().collect::<BTreeSet<_>>().len() != self.measures.len()
            || self.measures.iter().any(|m| !allowed.contains(m))
            || (self.view == View::Breakdown) != self.dimension.is_some()
            || [Dimension::Channel, Dimension::Region, Dimension::Product]
                .iter()
                .any(|d| {
                    self.filters
                        .get(*d)
                        .is_some_and(|v| !d.values().contains(&v))
                })
        {
            return Err("The portfolio query exceeds the permitted measures, dimensions, filters or history windows.".into());
        }
        Ok(())
    }
    fn keys(&self) -> Vec<String> {
        match self.view {
            View::Summary => vec!["all".into()],
            View::Comparison => vec!["current".into(), "previous".into()],
            View::Trend => (0..6).map(|i| format!("bucket_{i}")).collect(),
            View::Breakdown => {
                let dimension = self.dimension.expect("validated breakdown");
                dimension.values().iter().map(|s| s.to_string()).collect()
            }
        }
    }
    fn period(&self, index: usize, as_of: i64) -> (i64, i64) {
        let window = i64::from(self.window_secs);
        match self.view {
            View::Trend => {
                let start = as_of - window + index as i64 * (window / 6);
                (start, start + window / 6)
            }
            View::Comparison if index == 1 => (as_of - window * 2, as_of - window),
            _ => (as_of - window, as_of),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortfolioRow {
    pub key: String,
    pub period_start: i64,
    pub period_end: i64,
    pub sample_count: u64,
    pub values: BTreeMap<Measure, Option<f64>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub measure: Measure,
    pub current: Option<f64>,
    pub previous: Option<f64>,
    pub delta: Option<f64>,
    pub delta_unit: String,
    pub relative_percent: Option<f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortfolioSnapshot {
    pub tenant_id: String,
    pub query: PortfolioQuery,
    pub as_of: i64,
    pub watermark: i64,
    pub history_start: i64,
    pub history_kind: String,
    pub rows: Vec<PortfolioRow>,
    pub comparison: Vec<Comparison>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortfolioEvidence {
    #[serde(flatten)]
    pub snapshot: PortfolioSnapshot,
    pub source_id: String,
    pub observed_at: i64,
    pub coverage: String,
}
fn same(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.is_finite() && b.is_finite() && (a - b).abs() <= 1e-7 * b.abs().max(1.0)
        }
        _ => false,
    }
}
impl PortfolioSnapshot {
    pub fn validate(
        &self,
        tenant: &str,
        query: &PortfolioQuery,
        allowed: &[Measure],
        observed_at: i64,
        max_staleness: u32,
    ) -> Result<(), String> {
        query.validate(allowed)?;
        let invalid = || {
            "The portfolio source returned incomplete, stale or out-of-scope evidence.".to_string()
        };
        if self.tenant_id != tenant
            || &self.query != query
            || self.history_kind != "synthetic_seeded_and_live"
            || self.as_of <= 0
            || self.as_of > observed_at + 5
            || self.as_of < observed_at - i64::from(max_staleness)
            || self.watermark <= 0
            || self.watermark > self.as_of
            || self.watermark < observed_at - i64::from(max_staleness)
            || self.history_start <= 0
            || self.history_start
                > self.as_of
                    - i64::from(query.window_secs)
                        * if query.view == View::Comparison { 2 } else { 1 }
            || self.rows.len() > 12
            || self.rows.len() != query.keys().len()
        {
            return Err(invalid());
        }
        let measures: BTreeSet<_> = query.measures.iter().copied().collect();
        for (index, (row, key)) in self.rows.iter().zip(query.keys()).enumerate() {
            if row.key != key
                || (row.period_start, row.period_end) != query.period(index, self.as_of)
                || row.sample_count > 1_000_000_000
                || row.values.keys().copied().collect::<BTreeSet<_>>() != measures
            {
                return Err(invalid());
            }
            if query.view == View::Breakdown
                && query
                    .dimension
                    .and_then(|dimension| query.filters.get(dimension))
                    .is_some_and(|filter| filter != row.key)
                && row.sample_count != 0
            {
                return Err(invalid());
            }
            for (measure, value) in &row.values {
                if *measure == Measure::ApplicationCount {
                    if *value != Some(row.sample_count as f64) {
                        return Err(invalid());
                    }
                } else if measure.is_count() {
                    if value.is_none_or(|v| v > row.sample_count as f64) {
                        return Err(invalid());
                    }
                } else if (row.sample_count == 0) != value.is_none() {
                    return Err(invalid());
                }
                if value.is_some_and(|v| !measure.valid(v)) {
                    return Err(invalid());
                }
            }
            for (count, rate) in [
                (Measure::ManualReviewCount, Measure::ManualReviewRatePercent),
                (
                    Measure::IdentityMismatchCount,
                    Measure::IdentityMismatchRatePercent,
                ),
            ] {
                if let (Some(count), Some(rate)) = (row.values.get(&count), row.values.get(&rate)) {
                    let expected = count.and_then(|count| {
                        (row.sample_count > 0).then_some(count / row.sample_count as f64 * 100.0)
                    });
                    if !same(*rate, expected) {
                        return Err(invalid());
                    }
                }
            }
        }
        if query.view != View::Comparison {
            if !self.comparison.is_empty() {
                return Err(invalid());
            }
        } else {
            if self.comparison.len() != measures.len() {
                return Err(invalid());
            }
            let mut seen = BTreeSet::new();
            for comparison in &self.comparison {
                if !measures.contains(&comparison.measure) || !seen.insert(comparison.measure) {
                    return Err(invalid());
                }
                let current = self.rows[0].values[&comparison.measure];
                let previous = self.rows[1].values[&comparison.measure];
                let delta = current.zip(previous).map(|(c, p)| c - p);
                let relative = delta
                    .zip(previous)
                    .and_then(|(d, p)| (p != 0.0).then_some(d / p.abs() * 100.0));
                let numeric = if comparison.measure.is_count() {
                    comparison.current == current
                        && comparison.previous == previous
                        && comparison.delta == delta
                } else {
                    same(comparison.current, current)
                        && same(comparison.previous, previous)
                        && same(comparison.delta, delta)
                };
                if comparison.delta_unit != comparison.measure.delta_unit()
                    || !numeric
                    || !same(comparison.relative_percent, relative)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}
pub fn category_label(key: &str) -> String {
    match key {
        "all" => "All selected applications".into(),
        "current" => "Current period".into(),
        "previous" => "Previous period".into(),
        "web" => "Web".into(),
        "mobile" => "Mobile".into(),
        "partner" => "Partner".into(),
        "northeast" => "Northeast".into(),
        "southeast" => "Southeast".into(),
        "midwest" => "Midwest".into(),
        "west" => "West".into(),
        "personal_loan" => "Personal loan".into(),
        "auto_loan" => "Auto loan".into(),
        "credit_card" => "Credit card".into(),
        _ => key
            .strip_prefix("bucket_")
            .and_then(|i| i.parse::<usize>().ok())
            .map_or_else(|| "Unknown".into(), |i| format!("Interval {}", i + 1)),
    }
}
fn display(measure: Measure, value: Option<f64>) -> String {
    value.map_or_else(
        || "unavailable (no samples)".into(),
        |v| {
            if measure.is_count() {
                format!("{v:.0} applications")
            } else {
                format!("{v:.2} {}", measure.unit())
            }
        },
    )
}
impl PortfolioEvidence {
    pub fn answer(&self) -> String {
        let data = &self.snapshot;
        let mut findings = Vec::new();
        match data.query.view {
            View::Comparison => {
                for comparison in &data.comparison {
                    let change = comparison.delta.map_or_else(
                        || "change unavailable".into(),
                        |delta| format!("{delta:+.2} {}", comparison.delta_unit.replace('_', " ")),
                    );
                    findings.push(format!(
                        "{}: {}, previously {} ({change}).",
                        comparison.measure.label(),
                        display(comparison.measure, comparison.current),
                        display(comparison.measure, comparison.previous)
                    ));
                }
            }
            View::Breakdown => {
                for measure in &data.query.measures {
                    let populated = data
                        .rows
                        .iter()
                        .filter_map(|row| row.values[measure].map(|v| (row, v)))
                        .collect::<Vec<_>>();
                    let minimum = populated
                        .iter()
                        .map(|(_, value)| *value)
                        .min_by(f64::total_cmp)
                        .map(|minimum| {
                            let names = populated
                                .iter()
                                .filter(|(_, value)| *value == minimum)
                                .map(|(row, _)| category_label(&row.key))
                                .collect::<Vec<_>>()
                                .join(" and ");
                            format!(
                                "{}: {names}, {}.",
                                if *measure == Measure::MeanProcessingSeconds {
                                    "Fastest (lowest mean processing time)".to_string()
                                } else {
                                    format!("Lowest {}", measure.label().to_lowercase())
                                },
                                display(*measure, Some(minimum))
                            )
                        });
                    if *measure == Measure::MeanProcessingSeconds
                        && let Some(minimum) = &minimum
                    {
                        findings.push(minimum.clone());
                    }
                    if let Some(max) = populated.iter().map(|(_, v)| *v).max_by(f64::total_cmp) {
                        let leaders = populated
                            .iter()
                            .filter(|(_, v)| *v == max)
                            .map(|(row, _)| category_label(&row.key))
                            .collect::<Vec<_>>()
                            .join(" and ");
                        findings.push(format!(
                            "{leaders} {} the highest {}: {}.",
                            if leaders.contains(" and ") {
                                "share"
                            } else {
                                "has"
                            },
                            measure.label().to_lowercase(),
                            display(*measure, Some(max))
                        ));
                        if *measure != Measure::MeanProcessingSeconds
                            && let Some(minimum) = minimum
                        {
                            findings.push(minimum);
                        }
                    } else {
                        findings.push(format!(
                            "{} is unavailable: no matching samples.",
                            measure.label()
                        ));
                    }
                    // Keep every grouped value available to the fact selector.
                    // Extrema alone cannot answer a named pair of interior
                    // categories, and a missing value must stay unavailable.
                    findings.push(format!(
                        "{} by {}: {}.",
                        measure.label(),
                        data.query.dimension.expect("validated breakdown").id(),
                        data.rows
                            .iter()
                            .map(|row| format!(
                                "{}={}",
                                category_label(&row.key),
                                display(*measure, row.values[measure])
                            ))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ));
                }
            }
            View::Trend => {
                for measure in &data.query.measures {
                    findings.push(format!(
                        "{} across six equal intervals: {}.",
                        measure.label(),
                        data.rows
                            .iter()
                            .map(|row| display(*measure, row.values[measure]))
                            .collect::<Vec<_>>()
                            .join(" → ")
                    ));
                }
            }
            View::Summary => {
                for row in &data.rows {
                    for measure in &data.query.measures {
                        findings.push(format!(
                            "{}: {}.",
                            measure.label(),
                            display(*measure, row.values[measure])
                        ));
                    }
                }
            }
        }
        if data.query.measures.contains(&Measure::ApplicationCount)
            && data.query.view == View::Summary
        {
            let count = data.rows[0].sample_count;
            findings.push(format!("That is {:.2} applications/minute, computed from {count} applications over {} seconds.",count as f64*60.0/f64::from(data.query.window_secs),data.query.window_secs));
        }
        let filters = [Dimension::Channel, Dimension::Region, Dimension::Product]
            .iter()
            .filter_map(|d| {
                data.query
                    .filters
                    .get(*d)
                    .map(|v| format!("{}={}", d.id(), category_label(v)))
            })
            .collect::<Vec<_>>();
        findings.push(format!(
            "Window: {} minute{}{}. Filters: {}. Samples: {}.",
            data.query.window_secs / 60,
            if data.query.window_secs == 60 {
                ""
            } else {
                "s"
            },
            if data.query.view == View::Comparison {
                " versus the preceding equal period"
            } else {
                ""
            },
            if filters.is_empty() {
                "all permitted categories".to_string()
            } else {
                filters.join(", ")
            },
            data.rows
                .iter()
                .map(|row| format!("{} {}", category_label(&row.key), row.sample_count))
                .collect::<Vec<_>>()
                .join("; ")
        ));
        findings.push("Synthetic computed aggregates; these comparisons do not establish causes or individual credit decisions.".into());
        findings.join(" ")
    }
    pub fn presentation(&self, evidence_id: &str) -> Value {
        let mut value = serde_json::to_value(self).expect("finite validated evidence");
        value["evidence_id"] = json!(evidence_id);
        value["answer"] = json!(self.answer());
        value["measures"] = measure_catalog(&self.snapshot.query.measures);
        for (row, original) in value["rows"]
            .as_array_mut()
            .expect("rows")
            .iter_mut()
            .zip(&self.snapshot.rows)
        {
            row["label"] = json!(category_label(&original.key));
        }
        value
    }
}
pub fn measure_catalog(measures: &[Measure]) -> Value {
    json!(
        measures
            .iter()
            .map(|m| json!({"id":m,"label":m.label(),"unit":m.unit()}))
            .collect::<Vec<_>>()
    )
}
pub fn dataset(measures: &[Measure], source: &str, allowed: bool) -> Value {
    json!({"id":"synthetic_loan_applications","label":"Synthetic loan application history","source_id":source,"history_kind":"synthetic_seeded_and_live",
        "measures":measure_catalog(measures),"views":["summary","trend","breakdown","comparison"],"windows_secs":WINDOWS,
        "dimensions":([Dimension::Channel,Dimension::Region,Dimension::Product].iter().map(|dimension|json!({"id":dimension,"values":dimension.values().iter().map(|key|json!({"id":key,"label":category_label(key)})).collect::<Vec<_>>()})).collect::<Vec<_>>()),
        "max_rows":12,"trend_buckets":6,"coverage_policy":"complete_windows_only","can_query":allowed})
}
pub fn tool_schema(measures: &[Measure]) -> Value {
    json!({"type":"object","additionalProperties":false,"properties":{
        "view":{"type":"string","enum":["summary","trend","breakdown","comparison"]},"window_secs":{"type":"integer","enum":WINDOWS},
        "measures":{"type":"array","items":{"type":"string","enum":measures},"minItems":1,"maxItems":4},
        "dimension":{"type":"string","enum":["channel","region","product"]},
        "filters":{"type":"object","additionalProperties":false,"properties":{"channel":{"type":"string","enum":Dimension::Channel.values()},"region":{"type":"string","enum":Dimension::Region.values()},"product":{"type":"string","enum":Dimension::Product.values()}}}},
        "required":["view","window_secs","measures"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(view: View) -> PortfolioQuery {
        PortfolioQuery {
            view,
            window_secs: 900,
            measures: vec![
                Measure::ApplicationCount,
                Measure::ManualReviewCount,
                Measure::ManualReviewRatePercent,
            ],
            dimension: (view == View::Breakdown).then_some(Dimension::Channel),
            filters: Filters::default(),
        }
    }
    fn snapshot(query: &PortfolioQuery) -> PortfolioSnapshot {
        let rows = query
            .keys()
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                let (period_start, period_end) = query.period(index, 10_000);
                PortfolioRow {
                    key,
                    period_start,
                    period_end,
                    sample_count: 100,
                    values: query
                        .measures
                        .iter()
                        .map(|m| {
                            (
                                *m,
                                Some(match m {
                                    Measure::ApplicationCount => 100.0,
                                    Measure::ManualReviewCount
                                    | Measure::ManualReviewRatePercent => 20.0,
                                    _ => 2.0,
                                }),
                            )
                        })
                        .collect(),
                }
            })
            .collect();
        let comparison = if query.view == View::Comparison {
            query
                .measures
                .iter()
                .map(|m| Comparison {
                    measure: *m,
                    current: Some(if *m == Measure::ApplicationCount {
                        100.0
                    } else {
                        20.0
                    }),
                    previous: Some(if *m == Measure::ApplicationCount {
                        100.0
                    } else {
                        20.0
                    }),
                    delta: Some(0.0),
                    delta_unit: m.delta_unit().into(),
                    relative_percent: Some(0.0),
                })
                .collect()
        } else {
            vec![]
        };
        PortfolioSnapshot {
            tenant_id: "tenant-a".into(),
            query: query.clone(),
            as_of: 10_000,
            watermark: 9999,
            history_start: 2000,
            history_kind: "synthetic_seeded_and_live".into(),
            rows,
            comparison,
        }
    }
    #[test]
    fn all_views_validate_and_evidence_roundtrips_strictly() {
        for view in [
            View::Summary,
            View::Trend,
            View::Breakdown,
            View::Comparison,
        ] {
            let query = query(view);
            let snapshot = snapshot(&query);
            snapshot
                .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
                .unwrap();
            let evidence = PortfolioEvidence {
                snapshot,
                source_id: "approved-source".into(),
                observed_at: 10_000,
                coverage: "complete".into(),
            };
            let value = serde_json::to_value(&evidence).unwrap();
            let decoded: PortfolioEvidence = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(decoded.snapshot.query, query);
            let mut bad = value;
            bad["raw_rows"] = json!([]);
            assert!(serde_json::from_value::<PortfolioEvidence>(bad).is_err());
            assert!(evidence.answer().contains("15 minutes"));
        }
    }
    #[test]
    fn rejects_stale_foreign_missing_coverage_wrong_rows_and_noninteger_counts() {
        let query = query(View::Breakdown);
        let valid = snapshot(&query);
        for mut invalid in [
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            match invalid.0 {
                0 => invalid.1.tenant_id = "foreign".into(),
                1 => invalid.1.watermark = 9000,
                2 => invalid.1.history_start = 9500,
                3 => invalid.1.rows[0].period_start += 1,
                4 => {
                    invalid.1.rows[0]
                        .values
                        .insert(Measure::ManualReviewCount, Some(100.1));
                }
                5 => {
                    invalid.1.rows[0]
                        .values
                        .insert(Measure::ManualReviewCount, Some(101.0));
                }
                _ => invalid.1.rows[0].key = "east".into(),
            };
            assert!(
                invalid
                    .1
                    .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
                    .is_err()
            );
        }
    }
    #[test]
    fn empty_rows_preserve_nulls_and_comparison_delta_units_are_verified() {
        let query = query(View::Comparison);
        let mut snapshot = snapshot(&query);
        for row in &mut snapshot.rows {
            row.sample_count = 0;
            for (m, v) in &mut row.values {
                *v = m.is_count().then_some(0.0);
            }
        }
        for comparison in &mut snapshot.comparison {
            comparison.current = comparison.measure.is_count().then_some(0.0);
            comparison.previous = comparison.current;
            comparison.delta = comparison.current;
            comparison.relative_percent = None;
        }
        snapshot
            .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
            .unwrap();
        snapshot.rows[0]
            .values
            .insert(Measure::ManualReviewRatePercent, Some(0.0));
        assert!(
            snapshot
                .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
                .is_err()
        );
        let mut nonempty = self::snapshot(&query);
        nonempty.comparison[2].delta_unit = "percent".into();
        assert!(
            nonempty
                .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
                .is_err()
        );
        nonempty.comparison[2].delta_unit = "percentage_points".into();
        nonempty.comparison[2].delta = Some(5.0);
        assert!(
            nonempty
                .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
                .is_err()
        );
    }
    #[test]
    fn fastest_processing_answer_uses_lowest_source_value() {
        let mut query = query(View::Breakdown);
        query.measures = vec![Measure::MeanProcessingSeconds];
        let mut snapshot = snapshot(&query);
        for (index, row) in snapshot.rows.iter_mut().enumerate() {
            row.values.insert(
                Measure::MeanProcessingSeconds,
                Some(30.0 - index as f64 * 10.0),
            );
        }
        snapshot
            .validate("tenant-a", &query, &Measure::ALL, 10_000, 60)
            .unwrap();
        let evidence = PortfolioEvidence {
            snapshot,
            source_id: "source".into(),
            observed_at: 10_000,
            coverage: "complete".into(),
        };
        assert!(
            evidence
                .answer()
                .starts_with("Fastest (lowest mean processing time): Partner, 10.00 seconds.")
        );
        assert!(
            evidence
                .answer()
                .contains("Web has the highest mean processing time: 30.00 seconds.")
        );
    }
    #[test]
    fn query_rejects_unlisted_authority_and_limits_four_of_six_measures() {
        let base = serde_json::to_value(query(View::Summary)).unwrap();
        for field in ["tenant_id", "sql", "url", "raw_rows", "watch_secs"] {
            let mut bad = base.clone();
            bad[field] = json!("override");
            assert!(serde_json::from_value::<PortfolioQuery>(bad).is_err());
        }
        let mut query = query(View::Summary);
        query.measures = Measure::ALL.to_vec();
        assert!(query.validate(&Measure::ALL).is_err());
        query.measures.truncate(4);
        query.validate(&Measure::ALL).unwrap();
        query.filters.region = Some("east".into());
        assert!(query.validate(&Measure::ALL).is_err());
    }
}

#[cfg(test)]
mod consistency_tests {
    use super::*;
    #[test]
    fn contradictory_count_rate_and_approximately_equal_large_counts_fail() {
        let query:PortfolioQuery=serde_json::from_value(json!({"view":"summary","window_secs":60,"measures":["application_count","manual_review_count","manual_review_rate_percent"]})).unwrap();
        let mut snapshot:PortfolioSnapshot=serde_json::from_value(json!({"tenant_id":"a","query":query,"as_of":10000,"watermark":10000,"history_start":2000,"history_kind":"synthetic_seeded_and_live","rows":[{"key":"all","period_start":9940,"period_end":10000,"sample_count":100,"values":{"application_count":100,"manual_review_count":20,"manual_review_rate_percent":90}}],"comparison":[]})).unwrap();
        assert!(
            snapshot
                .validate("a", &query, &Measure::ALL, 10000, 60)
                .is_err()
        );
        snapshot.rows[0]
            .values
            .insert(Measure::ManualReviewRatePercent, Some(20.0));
        snapshot
            .validate("a", &query, &Measure::ALL, 10000, 60)
            .unwrap();
        snapshot.rows[0].sample_count = 999_999_900;
        snapshot.rows[0]
            .values
            .insert(Measure::ApplicationCount, Some(1_000_000_000.0));
        assert!(
            snapshot
                .validate("a", &query, &Measure::ALL, 10000, 60)
                .is_err()
        );
    }
}
