//! Versioned, bounded observations. These findings never authorize execution.
use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ExportRecord;

pub const DETECTOR_VERSION: u32 = 1;
pub const DETECTOR_CAP: usize = 8192;
const RULES: &[&str] = &[
    "approval_missing",
    "approval_lineage_mismatch",
    "action_lineage_mismatch",
    "audit_loss_recorded",
    "evidence_gap",
    "state_evicted",
    "restart_coverage_gap",
    "export_spool_failed",
    "export_webhook_failed",
    "export_syslog_failed",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub id: String,
    pub rule: String,
    pub sequence: i64,
    pub related_sequence: Option<i64>,
}

impl Finding {
    pub fn new(rule: &str, record: &ExportRecord, related_sequence: Option<i64>) -> Self {
        // The original record authenticator differentiates streams. This ID is
        // deterministic correlation, NOT an authentication signature.
        let identity = format!(
            "opaque:anomaly:v1\0{rule}\0{}\0{}\0{}\0{}",
            record.sequence_number,
            record.event_id,
            record.record_hash.as_deref().unwrap_or(""),
            related_sequence.map(|v| v.to_string()).unwrap_or_default()
        );
        let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
        // Group the nonsecret digest so the audit sanitizer's generic long
        // token pattern does not erase this correlation identifier.
        let id = format!(
            "{}-{}-{}-{}",
            &digest[..16],
            &digest[16..32],
            &digest[32..48],
            &digest[48..]
        );
        Self {
            schema: "opaque.anomaly.finding.v1".into(),
            id,
            rule: rule.into(),
            sequence: record.sequence_number,
            related_sequence,
        }
    }

    pub(super) fn event_id(&self) -> String {
        let s = self.id.replace('-', "");
        format!(
            "{}-{}-{}-{}-{}",
            &s[..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..32]
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    action: Option<String>,
    approval: Option<String>,
    sequence: i64,
    granted: bool,
    indeterminate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDetector {
    pub version: u32,
    pending: BTreeMap<String, Pending>,
    order: VecDeque<String>,
    pub last_rowid: i64,
    pub last_sequence: Option<i64>,
    last_timestamp: Option<i64>,
    pub health: BTreeMap<String, u64>,
    /// Persisted with the cursor before any alert delivery. Cleared only after
    /// the corresponding deterministic audit event is durably acknowledged.
    pub outbox: Vec<Finding>,
    pub failed_transports: std::collections::BTreeSet<String>,
}

impl Default for ApprovalDetector {
    fn default() -> Self {
        Self {
            version: DETECTOR_VERSION,
            pending: BTreeMap::new(),
            order: VecDeque::new(),
            last_rowid: 0,
            last_sequence: None,
            last_timestamp: None,
            health: BTreeMap::new(),
            outbox: Vec::new(),
            failed_transports: Default::default(),
        }
    }
}

fn action(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
        .cloned()
}

fn identifier(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .filter(|v| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control))
        .cloned()
}

impl ApprovalDetector {
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn valid(&self, cursor: i64) -> bool {
        self.version == DETECTOR_VERSION
            && self.last_rowid == cursor
            && self.last_sequence.is_some() == (cursor > 0)
            && self.last_sequence.is_none_or(|sequence| sequence >= 0)
            && self.pending.len() <= DETECTOR_CAP
            && self.order.len() == self.pending.len()
            && self
                .order
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.order.len()
            && self.order.iter().all(|id| self.pending.contains_key(id))
            && self.pending.iter().all(|(id, value)| {
                identifier(&Some(id.clone())).is_some()
                    && value
                        .action
                        .as_ref()
                        .is_none_or(|v| action(&Some(v.clone())).is_some())
                    && value
                        .approval
                        .as_ref()
                        .is_none_or(|v| identifier(&Some(v.clone())).is_some())
                    && value.sequence >= 0
            })
            && self
                .failed_transports
                .iter()
                .all(|name| matches!(name.as_str(), "spool" | "webhook" | "syslog"))
            && self.outbox.len() <= 4096
            && self
                .outbox
                .iter()
                .map(|f| &f.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.outbox.len()
            && self.outbox.iter().all(|f| {
                f.schema == "opaque.anomaly.finding.v1"
                    && RULES.contains(&f.rule.as_str())
                    && f.sequence >= 0
                    && f.related_sequence.is_none_or(|v| v >= 0)
            })
            && self.outbox.iter().all(|f| {
                f.id.len() == 67
                    && f.id.split('-').count() == 4
                    && f.id.split('-').all(|part| {
                        part.len() == 16
                            && part
                                .bytes()
                                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                    })
            })
    }

    pub(super) fn count(&mut self, name: &str) {
        let count = self.health.entry(name.into()).or_default();
        *count = count.saturating_add(1);
    }

    pub(super) fn coverage_gap(&mut self, reason: &str, record: &ExportRecord) -> Finding {
        self.pending.clear();
        self.order.clear();
        self.count(reason);
        Finding::new(reason, record, None)
    }

    /// Backward-compatible convenience; pump/report callers use all findings.
    pub fn observe(&mut self, record: &ExportRecord) -> Option<String> {
        self.observe_findings(record)
            .first()
            .map(|f| serde_json::to_string(f).expect("finding serializes"))
    }

    pub fn observe_findings(&mut self, record: &ExportRecord) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some(previous) = self.last_sequence {
            if record.sequence_number != previous.saturating_add(1)
                || record.rowid != self.last_rowid.saturating_add(1)
            {
                findings.push(self.coverage_gap("evidence_gap", record));
            }
        } else if record.sequence_number > 0 || record.rowid > 1 {
            self.count("prefix_unobserved");
        }
        if self
            .last_timestamp
            .is_some_and(|previous| record.ts_utc_ms < previous)
        {
            self.count("clock_regressions");
        }
        self.last_rowid = record.rowid;
        self.last_sequence = Some(record.sequence_number);
        self.last_timestamp = Some(record.ts_utc_ms);
        self.count("observed_records");
        if record.kind == "audit.dropped" {
            findings.push(Finding::new("audit_loss_recorded", record, None));
        }
        if record.kind == "audit.alert" {
            self.count("recorded_alert_events");
        }
        let Some(id) = identifier(&record.request_id) else {
            if matches!(
                record.kind.as_str(),
                "approval.required" | "approval.granted" | "operation.succeeded"
            ) {
                self.count("missing_request_identity");
            }
            return findings;
        };
        let current_action = action(&record.request_hash);
        let current_approval = identifier(&record.approval_id);
        match record.kind.as_str() {
            "approval.required" => {
                // Reusing a request ID starts a new observed round. Never allow
                // a grant from the old action/approval to satisfy the new one.
                if self.pending.contains_key(&id) {
                    self.order.retain(|value| value != &id);
                }
                if self.pending.len() == DETECTOR_CAP
                    && !self.pending.contains_key(&id)
                    && let Some(evicted) = self.order.pop_front()
                {
                    self.pending.remove(&evicted);
                    self.count("capacity_evictions");
                    findings.push(Finding::new("state_evicted", record, None));
                }
                if current_action.is_none() || current_approval.is_none() {
                    self.count("missing_lineage");
                }
                self.order.push_back(id.clone());
                self.pending.insert(
                    id,
                    Pending {
                        action: current_action,
                        approval: current_approval,
                        sequence: record.sequence_number,
                        granted: false,
                        indeterminate: false,
                    },
                );
            }
            "approval.granted" | "lease.hit" => {
                if let Some(pending) = self.pending.get_mut(&id) {
                    let mismatch = pending
                        .action
                        .as_ref()
                        .zip(current_action.as_ref())
                        .is_some_and(|(a, b)| a != b)
                        || pending
                            .approval
                            .as_ref()
                            .zip(current_approval.as_ref())
                            .is_some_and(|(a, b)| a != b);
                    if mismatch {
                        findings.push(Finding::new(
                            "approval_lineage_mismatch",
                            record,
                            Some(pending.sequence),
                        ));
                    } else if current_action.is_some()
                        && pending.action == current_action
                        && current_approval.is_some()
                        && pending.approval == current_approval
                        && record.kind == "approval.granted"
                    {
                        pending.granted = true;
                    } else {
                        // v1 lease.hit has no original grant/approval lineage.
                        // It is not evidence that this newly required round was met.
                        pending.indeterminate = true;
                        self.count("missing_lineage");
                    }
                }
            }
            "operation.succeeded" | "operation.failed" => {
                if let Some(pending) = self.pending.remove(&id) {
                    self.order.retain(|value| value != &id);
                    if record.kind == "operation.succeeded" {
                        match pending.action.as_ref().zip(current_action.as_ref()) {
                            Some((a, b)) if a != b => findings.push(Finding::new(
                                "action_lineage_mismatch",
                                record,
                                Some(pending.sequence),
                            )),
                            Some(_)
                                if !pending.granted
                                    && !pending.indeterminate
                                    && pending.approval.is_some() =>
                            {
                                findings.push(Finding::new(
                                    "approval_missing",
                                    record,
                                    Some(pending.sequence),
                                ))
                            }
                            None => self.count("missing_lineage"),
                            _ => {}
                        }
                    }
                } else if record.kind == "operation.succeeded" {
                    self.count("terminal_without_observed_requirement");
                }
            }
            _ => {}
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn record(index: i64, changes: &Value) -> ExportRecord {
        let mut value = json!({"schema":"opaque.audit.v1", "event_id":format!("event-{index}"),
            "rowid":index+1,"sequence_number":index,"ts_utc_ms":index*3000,
            "kind":"request.received","level":"info","record_hash":"c".repeat(64),
            "request_hash":"a".repeat(64),"request_id":"private-request","approval_id":"round"});
        value
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn shared_labeled_lifecycle_corpus_survives_restart_at_every_record() {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../../tests/fixtures/anomaly_lifecycle_v1.json"
        ))
        .unwrap();
        for case in cases {
            let mut state = ApprovalDetector::default();
            let mut rules = Vec::new();
            for (index, event) in case["events"].as_array().unwrap().iter().enumerate() {
                rules.extend(
                    state
                        .observe_findings(&record(index as i64, event))
                        .into_iter()
                        .map(|f| f.rule),
                );
                // Actual serialized state, not cloned memory, crosses every step.
                state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
                assert!(state.valid(index as i64 + 1));
            }
            assert_eq!(json!(rules), case["rules"], "{}", case["name"]);
            assert_eq!(
                json!(state.pending_count()),
                case["pending"],
                "{}",
                case["name"]
            );
            if let Some(health) = case.get("health") {
                for (name, count) in health.as_object().unwrap() {
                    assert_eq!(json!(state.health[name]), *count, "{}", case["name"]);
                }
            }
        }
    }

    #[test]
    fn capacity_and_sequence_gaps_are_visible_without_fabricated_missing_grants() {
        let mut state = ApprovalDetector::default();
        for index in 0..=DETECTOR_CAP {
            let findings = state.observe_findings(&record(
                index as i64,
                &json!({"kind":"approval.required","request_id":format!("req-{index}")}),
            ));
            assert_eq!(findings.len(), usize::from(index == DETECTOR_CAP));
        }
        assert_eq!(state.pending_count(), DETECTOR_CAP);
        assert_eq!(state.health["capacity_evictions"], 1);
        let findings = state.observe_findings(&record(
            DETECTOR_CAP as i64 + 2,
            &json!({"kind":"operation.succeeded","request_id":"req-1"}),
        ));
        assert_eq!(
            findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>(),
            ["evidence_gap"]
        );
        assert_eq!(state.pending_count(), 0);
        assert_eq!(state.health["terminal_without_observed_requirement"], 1);
    }

    #[test]
    fn terminal_cleanup_does_not_consume_capacity_and_new_round_does_not_reuse_grant() {
        let mut state = ApprovalDetector::default();
        for index in 0..DETECTOR_CAP + 2 {
            for (offset, kind) in [(0, "approval.required"), (1, "operation.failed")] {
                assert!(
                    state
                        .observe_findings(&record(
                            (index * 2 + offset) as i64,
                            &json!({"kind":kind,"request_id":format!("req-{index}")})
                        ))
                        .is_empty()
                );
            }
        }
        assert_eq!(state.pending_count(), 0);
        assert!(!state.health.contains_key("capacity_evictions"));
        let mut state = ApprovalDetector::default();
        for (index, event) in [
            json!({"kind":"approval.required"}),
            json!({"kind":"approval.granted"}),
            json!({"kind":"approval.required","approval_id":"new-round"}),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                state
                    .observe_findings(&record(index as i64, event))
                    .is_empty()
            );
        }
        assert_eq!(
            state.observe_findings(&record(3, &json!({"kind":"operation.succeeded"})))[0].rule,
            "approval_missing"
        );
    }

    #[test]
    fn stable_finding_ids_match_offline_encoding_and_omit_metadata() {
        let original = record(1, &json!({"kind":"operation.succeeded"}));
        let first = Finding::new("approval_missing", &original, Some(0));
        assert_eq!(first, Finding::new("approval_missing", &original, Some(0)));
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("private-request")
        );
        let mut changed = original;
        changed.record_hash = Some("d".repeat(64));
        assert_ne!(
            first.id,
            Finding::new("approval_missing", &changed, Some(0)).id
        );
    }
}
