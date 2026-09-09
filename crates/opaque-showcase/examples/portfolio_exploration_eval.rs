//! Explicit, read-only live model qualification. These synthetic cases prove
//! planner/selector behavior only, never authenticated source access or consent.
use clap::Parser;
use opaque_showcase::{
    chat::{ChatModel, ExplorationPlan, ModelConfig},
    exploration::Finding,
    portfolio::{Dimension, Measure, View},
};
use serde_json::{Value, json};
use std::{io::Write, path::PathBuf, time::Instant};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    model: String,
    /// An explicit new private output file. Existing files are never replaced.
    #[arg(long)]
    output: PathBuf,
    /// Run one held-out case while diagnosing the configured model contract.
    #[arg(long)]
    case: Option<String>,
}

fn matches_case(id: &str, plan: &ExplorationPlan) -> bool {
    let ExplorationPlan::Query {
        interpretation,
        queries,
    } = plan
    else {
        return match id {
            "borrowers" | "unavailable-history" | "scores" => {
                matches!(plan, ExplorationPlan::Unsupported { .. })
            }
            "ambiguous-flags" => matches!(plan, ExplorationPlan::Clarify { .. }),
            "causal-limit" => matches!(plan, ExplorationPlan::Unsupported { .. }),
            _ => false,
        };
    };
    if [
        "overview",
        "investigate",
        "channel-contrast",
        "slowest-product",
        "mismatch-trend",
        "causal-limit",
    ]
    .contains(&id)
        && queries.iter().any(|query| query.window_secs != 900)
    {
        return false;
    }
    match id {
        "overview" => {
            queries.len() >= 2
                && queries.iter().all(|q| q.window_secs == 900)
                && queries
                    .iter()
                    .any(|q| q.view != queries[0].view || q.dimension != queries[0].dimension)
                && queries
                    .iter()
                    .flat_map(|q| q.measures.iter())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    >= 2
                && !interpretation.contains('?')
        }
        "change" => queries
            .iter()
            .any(|q| q.view == View::Comparison && q.window_secs == 900),
        "investigate" => queries.iter().any(|q| {
            q.view == View::Breakdown
                && q.measures.iter().any(|m| {
                    [Measure::ManualReviewCount, Measure::ManualReviewRatePercent].contains(m)
                })
        }),
        "channel-contrast" => {
            queries.iter().any(|q| {
                q.view == View::Breakdown
                    && q.dimension == Some(Dimension::Channel)
                    && q.measures.contains(&Measure::ManualReviewRatePercent)
                    && q.filters == Default::default()
            }) || (["mobile", "partner"].iter().all(|value| {
                queries.iter().any(|q| {
                    q.filters.channel.as_deref() == Some(value)
                        && q.measures.contains(&Measure::ManualReviewRatePercent)
                        && q.filters.region.is_none()
                        && q.filters.product.is_none()
                })
            }))
        }
        "filtered-rate" => queries.iter().any(|q| {
            q.window_secs == 1800
                && q.filters.region.as_deref() == Some("west")
                && q.filters.product.as_deref() == Some("auto_loan")
                && q.filters.channel.is_none()
                && q.measures.contains(&Measure::ManualReviewRatePercent)
        }),
        "slowest-product" => queries.iter().any(|q| {
            q.view == View::Breakdown
                && q.dimension == Some(Dimension::Product)
                && q.measures.contains(&Measure::MeanProcessingSeconds)
                && q.filters == Default::default()
        }),
        "mismatch-trend" => queries.iter().any(|q| {
            // The question asks broadly how rates move over time; either
            // bucketed observations or an adjacent-period delta answers it.
            matches!(q.view, View::Trend | View::Comparison)
                && q.measures.contains(&Measure::IdentityMismatchRatePercent)
                && q.filters == Default::default()
        }),
        "website-count" => queries.iter().any(|q| {
            q.window_secs == 300
                && q.filters.channel.as_deref() == Some("web")
                && q.measures.contains(&Measure::ManualReviewCount)
                && q.filters.region.is_none()
                && q.filters.product.is_none()
        }),
        "causal-limit" => {
            queries.iter().any(|q| {
                q.measures.contains(&Measure::MeanProcessingSeconds)
                    && (q.filters.channel.as_deref() == Some("mobile")
                        || q.dimension == Some(Dimension::Channel))
            }) && {
                let lower = interpretation.to_ascii_lowercase();
                lower.contains("caus")
                    && ["cannot", "can't", "not "]
                        .iter()
                        .any(|word| lower.contains(word))
            }
        }
        _ => false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&args.output)?;
    let model = ChatModel::new(ModelConfig::OpenaiCompatible {
        base_url: args.base_url.clone(),
        model: args.model.clone(),
        allow_loopback_http: true,
    })?;
    let cases = [
        ("overview", "What stands out in our portfolio?"),
        ("change", "What changed in the last 15 minutes?"),
        (
            "investigate",
            "Where should I investigate unusual manual review burden?",
        ),
        (
            "channel-contrast",
            "Are applications from the phone channel sent to manual checks at a higher rate than partner submissions?",
        ),
        (
            "filtered-rate",
            "Give me the manual review percentage for auto loans in the West during the last 30 minutes.",
        ),
        (
            "slowest-product",
            "Which lending product takes longest on average?",
        ),
        (
            "mismatch-trend",
            "How are identity mismatch rates moving over time?",
        ),
        (
            "website-count",
            "How many applications reached manual checks on the website over the last five minutes?",
        ),
        ("causal-limit", "Why are mobile applications slower?"),
        ("ambiguous-flags", "How many applications were flagged?"),
        ("borrowers", "Show me the raw borrower records."),
        ("unavailable-history", "What changed yesterday?"),
        ("scores", "What is the average credit score?"),
    ];
    let mut results = Vec::new();
    for (id, question) in cases {
        if args.case.as_deref().is_some_and(|chosen| chosen != id) {
            continue;
        }
        let start = Instant::now();
        let (passed, result) = match model.plan_exploration(question, &Measure::ALL).await {
            Ok(plan) => (matches_case(id, &plan), serde_json::to_value(plan)?),
            Err(error) => (false, json!({"error":error})),
        };
        eprintln!(
            "{id}: {} ({} ms)",
            if passed { "PASS" } else { "FAIL" },
            start.elapsed().as_millis()
        );
        results.push(json!({"case":id,"question":question,"passed":passed,"duration_ms":start.elapsed().as_millis(),"result":result}));
    }
    if args.case.is_none() || args.case.as_deref() == Some("selection") {
        // Fixed synthetic computation fixtures are supplied as trusted facts;
        // no language model generated these values and no live source is read.
        let facts=vec![
            Finding{id:"q1:application_count".into(),evidence_id:"synthetic-computation-a".into(),text:"Last 15 minutes: 120 applications from 120 samples.".into()},
            Finding{id:"q2:manual_review_rate_percent".into(),evidence_id:"synthetic-computation-b".into(),text:"Last 15 minutes: manual review rate 5.00 %, 6 reviews from 120 applications.".into()},
            Finding{id:"q3:mean_processing_seconds".into(),evidence_id:"synthetic-computation-c".into(),text:"Last 15 minutes: mobile mean processing time 42.00 seconds; web mean processing time 30.00 seconds. Each channel has 40 samples.".into()},
        ];
        for (question, expected) in [
            ("How many applications came in?", "q1:application_count"),
            (
                "What is our manual review share?",
                "q2:manual_review_rate_percent",
            ),
            (
                "How does mobile processing compare with the website?",
                "q3:mean_processing_seconds",
            ),
        ] {
            let start = Instant::now();
            let (passed, result) = match model.select_findings(question, &facts).await {
                Ok(ids) => (ids == [expected.to_owned()], json!({"finding_ids":ids})),
                Err(error) => (false, json!({"error":error})),
            };
            eprintln!(
                "selection: {} ({} ms)",
                if passed { "PASS" } else { "FAIL" },
                start.elapsed().as_millis()
            );
            results.push(json!({"case":"selection","question":question,"passed":passed,"duration_ms":start.elapsed().as_millis(),"result":result}));
        }
    }
    if results.is_empty() {
        return Err("no matching evaluation case".into());
    }
    let passed = results.iter().filter(|row| row["passed"] == true).count();
    let summary: Value = json!({"kind":"live_model_protocol_evaluation","model":args.model,"base_url":args.base_url,"synthetic_cases":true,"live_source_verified":false,"human_approval_verified":false,"passed":passed,"total":results.len(),"results":results});
    serde_json::to_writer_pretty(&mut output, &summary)?;
    writeln!(output)?;
    output.sync_all()?;
    println!(
        "{passed}/{} passed; private report: {}",
        summary["total"],
        args.output.display()
    );
    if passed != summary["total"].as_u64().unwrap() as usize {
        std::process::exit(1);
    }
    Ok(())
}
