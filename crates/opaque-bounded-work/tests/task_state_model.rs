//! Bounded sequential conformance against the real SQLite TaskStore.
//!
//! Scope: one schema-1 publish slot, one owner, two request identities, valid
//! sanitized outcomes, and two logical instants (creation and exact expiry).
//! Approval is an internal store transition with explicitly synthetic provenance.
//! There is no provider, socket, reviewer, wall-clock wait, or signature claim.
//!
//! An independent authority/charge model generates the reachable abstract graph.
//! Every outgoing edge is replayed from its shortest witness in a fresh database;
//! the complete observable record is checked after every prefix, including reopen.
//! Histories reaching the same model state are merged. This is a bounded model
//! check, not exhaustive concurrent, multi-slot, corruption, or crash-I/O testing.
//!
//! The separate two-slot tests below enumerate a declared interleaving alphabet
//! and compare actual concurrent outcomes with its independent serial oracle.
//! They do not extend or replace the original one-slot graph's fixed counts.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

use opaque_bounded_work::task_store::{TaskStore, TaskStoreError};
use opaque_core::task::{
    PublishAction, SlotOutcome, SlotState, TaskApprovalMode, TaskManifest, TaskRecord, TaskState,
};

const CREATED: i64 = 1_800_000_000;
const LIFETIME: u64 = 60;
const OWNER: &str = "uid:7582:workspace:state-model";
const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Time {
    Live,
    Deadline,
}
impl Time {
    fn unix(self) -> i64 {
        CREATED
            + if self == Self::Deadline {
                LIFETIME as i64
            } else {
                0
            }
    }
}

// These are authority facts, deliberately separate from TaskState/SlotState.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Authority {
    Unclaimed,
    Claimed,
    Succeeded,
    Closed,
    Withdrawn,
    TimedOut,
}
impl Authority {
    fn active(self) -> bool {
        matches!(self, Self::Unclaimed | Self::Claimed)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Request {
    First,
    Other,
}
impl Request {
    fn text(self) -> &'static str {
        match self {
            Self::First => "request-first",
            Self::Other => "request-other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ResultKind {
    Accepted,
    Rejected,
    Unknown,
    Interrupted,
}
impl ResultKind {
    fn wire(self) -> SlotOutcome {
        let (state, code) = match self {
            Self::Accepted => (SlotState::ApiAccepted, "api_accepted"),
            Self::Rejected => (SlotState::Rejected, "provider_rejected"),
            Self::Unknown => (SlotState::Unknown, "transport_unknown"),
            Self::Interrupted => (SlotState::Unknown, "interrupted"),
        };
        SlotOutcome {
            state,
            code: code.into(),
            provider_run_id: None,
            inference_receipt: None,
            ssh_receipt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Action {
    Claim,
    Approve,
    WrongDigest,
    Reserve(Request),
    Dispatch(Request),
    Complete(Request, ResultKind),
    Finish,
    Revoke,
    Expire,
    Reopen,
}
const ACTIONS: [Action; 17] = [
    Action::Claim,
    Action::Approve,
    Action::WrongDigest,
    Action::Reserve(Request::First),
    Action::Reserve(Request::Other),
    Action::Dispatch(Request::First),
    Action::Dispatch(Request::Other),
    Action::Complete(Request::First, ResultKind::Accepted),
    Action::Complete(Request::First, ResultKind::Rejected),
    Action::Complete(Request::First, ResultKind::Unknown),
    Action::Complete(Request::Other, ResultKind::Accepted),
    Action::Complete(Request::Other, ResultKind::Rejected),
    Action::Complete(Request::Other, ResultKind::Unknown),
    Action::Finish,
    Action::Revoke,
    Action::Expire,
    Action::Reopen,
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Model {
    authority: Authority,
    approved: bool,
    // A consumed allowance has an immutable owner even after uncertainty.
    charged_to: Option<Request>,
    result: Option<ResultKind>,
    finished: Option<Time>,
    time: Time,
    successful_reservations: u8,
}
impl Model {
    fn planned() -> Self {
        Self {
            authority: Authority::Unclaimed,
            approved: false,
            charged_to: None,
            result: None,
            finished: None,
            time: Time::Live,
            successful_reservations: 0,
        }
    }

    fn in_flight(&self) -> bool {
        self.charged_to.is_some() && self.result.is_none()
    }

    /// Reference rules use authority predicates and an irreversible charge,
    /// without calling production transition, validation, or recovery helpers.
    fn apply(&mut self, action: Action) -> bool {
        match action {
            Action::Claim if self.authority == Authority::Unclaimed => {
                self.authority = Authority::Claimed;
            }
            Action::Approve if self.authority == Authority::Claimed && !self.approved => {
                self.approved = true;
            }
            Action::Reserve(request)
                if self.authority == Authority::Claimed
                    && self.approved
                    && self.charged_to.is_none() =>
            {
                self.charged_to = Some(request);
                self.successful_reservations += 1;
            }
            Action::Dispatch(request)
                if self.authority == Authority::Claimed
                    && self.approved
                    && self.in_flight()
                    && self.charged_to == Some(request) => {}
            Action::Complete(request, result)
                if self.in_flight() && self.charged_to == Some(request) =>
            {
                self.result = Some(result);
                self.finished = Some(self.time);
                if self.authority == Authority::Claimed {
                    self.authority = if result == ResultKind::Accepted {
                        Authority::Succeeded
                    } else {
                        Authority::Closed
                    };
                }
            }
            Action::Finish if self.authority != Authority::Unclaimed => {
                if self.in_flight() {
                    self.result = Some(ResultKind::Interrupted);
                    self.finished = Some(self.time);
                }
                if self.authority == Authority::Claimed {
                    self.authority = Authority::Closed;
                }
            }
            Action::Revoke => {
                if self.authority.active() {
                    self.authority = Authority::Withdrawn;
                }
            }
            Action::Expire => {
                self.time = Time::Deadline;
                if self.authority.active() {
                    self.authority = Authority::TimedOut;
                }
            }
            Action::Reopen => {
                if self.in_flight() {
                    self.result = Some(ResultKind::Interrupted);
                    // Recovery must not invent the provider completion time.
                    self.finished = None;
                }
                if self.authority == Authority::Claimed {
                    self.authority = Authority::Closed;
                }
            }
            _ => return false,
        }
        true
    }
}

fn manifest() -> TaskManifest {
    TaskManifest {
        schema_version: 1,
        title: "State model: one fixed publish slot".into(),
        expires_in_secs: LIFETIME,
        github_api_url: "https://api.github.com".into(),
        vault_api_url: "https://vault.example.invalid".into(),
        actions: vec![
            PublishAction {
                repo: "fixture/state-model".into(),
                repository_id: 1,
                secret_name: "MODEL_VALUE".into(),
                value_ref: "vault:kv/data/state-model?version=1#VALUE".into(),
                github_token_ref: Some("env:MODEL_GITHUB_TOKEN".into()),
            }
            .into(),
        ],
    }
}

struct Database {
    store: Option<TaskStore>,
    path: PathBuf,
    original: TaskRecord,
    _directory: tempfile::TempDir,
}
impl Database {
    fn plan() -> Self {
        Self::plan_manifest(manifest())
    }

    fn plan_manifest(manifest: TaskManifest) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.sqlite3");
        let store = TaskStore::open(&path).unwrap();
        let original = store.create(OWNER, manifest, CREATED).unwrap();
        Self {
            store: Some(store),
            path,
            original,
            _directory: directory,
        }
    }

    fn apply(&mut self, action: Action, now: i64) -> bool {
        if action == Action::Reopen {
            drop(self.store.take());
            self.store = Some(TaskStore::open(&self.path).expect("reopen actual SQLite ledger"));
            return true;
        }
        let store = self.store.as_ref().unwrap();
        let id = &self.original.id;
        let slot = &self.original.slots[0].id;
        let result = match action {
            Action::Claim => store.claim(id, OWNER, now).map(|_| ()),
            Action::Approve | Action::WrongDigest => store
                .approve(
                    id,
                    OWNER,
                    if action == Action::WrongDigest {
                        "wrong-digest"
                    } else {
                        &self.original.manifest_digest
                    },
                    TaskApprovalMode::InsecureTest,
                    now,
                )
                .map(|_| ()),
            Action::Reserve(request) => store
                .reserve_slot(id, OWNER, slot, request.text(), now)
                .map(|_| ()),
            Action::Dispatch(request) => {
                store.authorize_dispatch(id, OWNER, slot, request.text(), now)
            }
            Action::Complete(request, result) => store
                .finalize_slot(id, OWNER, slot, request.text(), result.wire(), now)
                .map(|_| ()),
            Action::Finish => store.finish_run(id, OWNER, now).map(|_| ()),
            Action::Revoke => store.revoke(id, OWNER, now).map(|_| ()),
            Action::Expire => store.get(id, OWNER, now).map(|_| ()),
            Action::Reopen => unreachable!(),
        };
        match result {
            Ok(()) => true,
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        TaskStoreError::AlreadyClaimed
                            | TaskStoreError::InvalidTransition
                            | TaskStoreError::NotApproved
                            | TaskStoreError::DigestMismatch
                            | TaskStoreError::SlotConsumed
                            | TaskStoreError::RequestMismatch
                            | TaskStoreError::Revoked
                            | TaskStoreError::Expired
                    ),
                    "unexpected non-lifecycle failure for {action:?}: {error:?}"
                );
                false
            }
        }
    }

    fn observe(&self) -> TaskRecord {
        // Read committed bytes independently: checking through get() alone
        // could conceal a transition that was never actually persisted.
        let connection = rusqlite::Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (owner, encoded): (String, String) = connection
            .query_row(
                "SELECT owner_key, record FROM bounded_tasks WHERE id=?1",
                [&self.original.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(owner, OWNER);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM bounded_tasks", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        serde_json::from_str(&encoded).unwrap()
    }

    fn assert_matches(&self, model: &Model, case: &str, prefix: &[Action]) {
        let actual = self.observe();
        let context = format!("{case} prefix={prefix:?} model={model:?}");
        let expected_task = match model.authority {
            Authority::Unclaimed => TaskState::Planned,
            Authority::Claimed => TaskState::Running,
            Authority::Succeeded => TaskState::Completed,
            Authority::Closed => TaskState::Partial,
            Authority::Withdrawn => TaskState::Revoked,
            Authority::TimedOut => TaskState::Expired,
        };
        assert_eq!(actual.state, expected_task, "{context}");
        assert_eq!(
            actual.approved_at,
            model.approved.then_some(CREATED),
            "{context}"
        );
        assert_eq!(
            actual.approval_mode,
            model.approved.then_some(TaskApprovalMode::InsecureTest),
            "{context}"
        );
        assert_eq!(actual.slots.len(), 1, "{context}");
        let slot = &actual.slots[0];
        let expected_slot = match model.result {
            Some(result) => result.wire().state,
            None if model.charged_to.is_some() => SlotState::Reserved,
            None => SlotState::Pending,
        };
        assert_eq!(slot.state, expected_slot, "{context}");
        assert_eq!(
            slot.request_id.as_deref(),
            model.charged_to.map(Request::text),
            "{context}"
        );
        assert_eq!(
            slot.reserved_at,
            model.charged_to.map(|_| CREATED),
            "{context}"
        );
        assert_eq!(
            slot.finished_at,
            model.finished.map(Time::unix),
            "{context}"
        );
        assert_eq!(
            slot.outcome,
            model.result.map(ResultKind::wire),
            "{context}"
        );
        assert_eq!(
            usize::from(slot.reserved_at.is_some()),
            usize::from(model.successful_reservations),
            "{context}"
        );

        // The lifecycle cannot change any planned authority or add evidence.
        assert_eq!(actual.id, self.original.id, "{context}");
        assert_eq!(actual.manifest, self.original.manifest, "{context}");
        assert_eq!(
            actual.manifest_digest, self.original.manifest_digest,
            "{context}"
        );
        assert_eq!(actual.owner_key, self.original.owner_key, "{context}");
        assert_eq!(actual.tenant, self.original.tenant, "{context}");
        assert_eq!(actual.created_at, CREATED, "{context}");
        assert_eq!(actual.expires_at, CREATED + LIFETIME as i64, "{context}");
        assert_eq!(slot.id, self.original.slots[0].id, "{context}");
        assert_eq!(slot.action, self.original.slots[0].action, "{context}");
        assert!(actual.workstation_receipt.is_none(), "{context}");
        assert!(actual.release_observation.is_none(), "{context}");
    }
}

fn replay(case: &str, sequence: &[Action]) -> usize {
    let mut actual = Database::plan();
    let mut model = Model::planned();
    actual.assert_matches(&model, case, &[]);
    for (index, &action) in sequence.iter().enumerate() {
        let before = model.clone();
        let expected_success = model.apply(action);
        let success = actual.apply(action, model.time.unix());
        assert_eq!(
            success,
            expected_success,
            "{case} prefix={:?}",
            &sequence[..=index]
        );
        assert!(
            model.successful_reservations <= 1,
            "{case}: allowance exceeded"
        );
        if before.charged_to.is_some() {
            assert_eq!(
                model.charged_to, before.charged_to,
                "{case}: charge refunded/reassigned"
            );
        }
        if !before.authority.active() {
            assert_eq!(
                model.authority, before.authority,
                "{case}: terminal task resurrected"
            );
        }
        actual.assert_matches(&model, case, &sequence[..=index]);
    }
    // Includes the initial real plan/create transition and its persisted check.
    sequence.len() + 1
}

#[test]
fn bounded_task_store_matches_reference_state_graph() {
    use Action::*;
    use Request::{First, Other};
    use ResultKind::{Accepted, Unknown};

    // Stable scenario identifiers complement graph counts: losing a critical
    // witness must not be hidden by an unrelated increase in explored edges.
    let cases: [(&str, &[Action]); 8] = [
        (
            "TSM-01-success-is-terminal",
            &[
                Claim,
                Approve,
                Reserve(First),
                Complete(First, Accepted),
                Reopen,
                Expire,
                Claim,
                Reserve(Other),
            ],
        ),
        (
            "TSM-02-unknown-stays-charged",
            &[
                Claim,
                Approve,
                Reserve(First),
                Complete(First, Unknown),
                Reopen,
                Reserve(Other),
            ],
        ),
        (
            "TSM-03-recovery-does-not-invent-completion-time",
            &[
                Claim,
                Approve,
                Reserve(First),
                Reopen,
                Finish,
                Complete(First, Accepted),
            ],
        ),
        (
            "TSM-04-revocation-preserves-inflight-result",
            &[
                Claim,
                Approve,
                Reserve(First),
                Revoke,
                Dispatch(First),
                Complete(First, Accepted),
                Reopen,
            ],
        ),
        (
            "TSM-05-exact-expiry-preserves-inflight-result",
            &[
                Claim,
                Approve,
                Reserve(First),
                Expire,
                Dispatch(First),
                Complete(First, Accepted),
                Reopen,
            ],
        ),
        (
            "TSM-06-denied-approval-cannot-resume",
            &[Claim, Finish, Reopen, Approve, Reserve(First)],
        ),
        (
            "TSM-07-reservation-owner-cannot-be-replaced",
            &[
                Claim,
                Approve,
                Reserve(Other),
                Reserve(First),
                Dispatch(First),
                Complete(First, Accepted),
                Complete(Other, Accepted),
            ],
        ),
        (
            "TSM-08-expiry-before-claim",
            &[Expire, Claim, Approve, Reserve(First), Reopen],
        ),
    ];
    assert_eq!(
        cases
            .iter()
            .map(|(id, _)| id)
            .collect::<BTreeSet<_>>()
            .len(),
        cases.len()
    );
    let mut checks = 0;
    for (id, sequence) in &cases {
        checks += replay(id, sequence);
    }

    let initial = Model::planned();
    let mut seen = BTreeSet::from([initial.clone()]);
    let mut queue = VecDeque::from([(initial, Vec::<Action>::new())]);
    let mut edges = 0;
    let mut allowed = 0;
    let mut denied = 0;
    let mut max_depth = 0;
    let mut action_outcomes = BTreeMap::<Action, (usize, usize)>::new();
    while let Some((model, witness)) = queue.pop_front() {
        assert!(
            witness.len() < MAX_DEPTH,
            "model frontier exceeded declared bound"
        );
        max_depth = max_depth.max(witness.len());
        for action in ACTIONS {
            let mut next = model.clone();
            let permitted = next.apply(action);
            let counts = action_outcomes.entry(action).or_default();
            if permitted {
                allowed += 1;
                counts.0 += 1;
            } else {
                denied += 1;
                counts.1 += 1;
            }
            let mut sequence = witness.clone();
            sequence.push(action);
            checks += replay(&format!("TSM-GRAPH-{edges:04}"), &sequence);
            edges += 1;
            if seen.insert(next.clone()) {
                queue.push_back((next, sequence));
            }
        }
    }
    assert_eq!(edges, seen.len() * ACTIONS.len());
    // Fixed coverage for this declared alphabet/model. Change these only with
    // a reviewed scope change; a smaller or truncated graph must fail loudly.
    assert_eq!(
        (seen.len(), edges, allowed, denied, max_depth, checks),
        (79, 1343, 345, 998, 6, 8848),
        "bounded reference graph coverage changed"
    );
    assert!(allowed > 0 && denied > 0);
    for action in ACTIONS {
        let (yes, no) = action_outcomes[&action];
        if action == WrongDigest {
            assert_eq!(yes, 0, "changed digest must never approve");
        } else {
            assert!(yes > 0, "missing positive transition: {action:?}");
        }
        if !matches!(action, Revoke | Expire | Reopen) {
            assert!(no > 0, "missing negative transition: {action:?}");
        }
    }
    for authority in [
        Authority::Unclaimed,
        Authority::Claimed,
        Authority::Succeeded,
        Authority::Closed,
        Authority::Withdrawn,
        Authority::TimedOut,
    ] {
        assert!(
            seen.iter().any(|state| state.authority == authority),
            "unvisited task phase: {authority:?}"
        );
    }
    assert!(
        seen.iter()
            .any(|state| state.result == Some(ResultKind::Interrupted)
                && state.finished.is_none()
                && state.charged_to.is_some())
    );
    println!(
        "TASK_MODEL_COVERAGE {}",
        serde_json::json!({
            "schema_version": 1, "fixed_cases": cases.len(), "abstract_states": seen.len(),
            "abstract_edges": edges, "allowed_edges": allowed, "denied_edges": denied,
            "fresh_database_sequences": edges + cases.len(), "persisted_transition_checks": checks,
            "max_witness_depth": max_depth, "declared_depth_bound": MAX_DEPTH,
            "slots": 1, "request_identities": 2, "logical_instants": 2,
            "wall_clock_sleeps": 0, "provider_calls": 0
        })
    );
}

// This oracle has no SQLite/TaskStore transitions. Authority and immutable
// charges are independent facts; record construction is observation mapping.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MultiAction {
    Reserve(usize),
    Dispatch(usize),
    Complete(usize, ResultKind),
    Revoke,
    Reopen,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Charge {
    reserved: bool,
    result: Option<ResultKind>,
    finished: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MultiModel {
    authority: Authority,
    slots: [Charge; 2],
}

impl MultiModel {
    fn approved() -> Self {
        Self {
            authority: Authority::Claimed,
            slots: [Charge::default(); 2],
        }
    }

    fn apply(&mut self, action: MultiAction) -> bool {
        match action {
            MultiAction::Reserve(index)
                if self.authority == Authority::Claimed && !self.slots[index].reserved =>
            {
                self.slots[index].reserved = true;
            }
            MultiAction::Dispatch(index)
                if self.authority == Authority::Claimed
                    && self.slots[index].reserved
                    && self.slots[index].result.is_none() => {}
            MultiAction::Complete(index, result)
                if self.slots[index].reserved && self.slots[index].result.is_none() =>
            {
                self.slots[index].result = Some(result);
                self.slots[index].finished = true;
                if self.authority == Authority::Claimed
                    && self.slots.iter().all(|slot| slot.result.is_some())
                {
                    self.authority = if self
                        .slots
                        .iter()
                        .all(|slot| slot.result == Some(ResultKind::Accepted))
                    {
                        Authority::Succeeded
                    } else {
                        Authority::Closed
                    };
                }
            }
            MultiAction::Revoke => {
                if self.authority == Authority::Claimed {
                    self.authority = Authority::Withdrawn;
                }
            }
            MultiAction::Reopen => {
                for slot in &mut self.slots {
                    if slot.reserved && slot.result.is_none() {
                        slot.result = Some(ResultKind::Interrupted);
                    }
                }
                if self.authority == Authority::Claimed {
                    self.authority = Authority::Closed;
                }
            }
            _ => return false,
        }
        true
    }

    fn record(&self, plan: &TaskRecord) -> TaskRecord {
        let mut expected = plan.clone();
        expected.state = match self.authority {
            Authority::Claimed => TaskState::Running,
            Authority::Succeeded => TaskState::Completed,
            Authority::Closed => TaskState::Partial,
            Authority::Withdrawn => TaskState::Revoked,
            other => panic!("outside the two-slot model: {other:?}"),
        };
        expected.approved_at = Some(CREATED);
        expected.approval_mode = Some(TaskApprovalMode::InsecureTest);
        for (index, charge) in self.slots.iter().enumerate() {
            let slot = &mut expected.slots[index];
            slot.state = match charge.result {
                Some(result) => result.wire().state,
                None if charge.reserved => SlotState::Reserved,
                None => SlotState::Pending,
            };
            slot.request_id = charge.reserved.then(|| multi_request(index).into());
            slot.reserved_at = charge.reserved.then_some(CREATED);
            slot.finished_at = charge.finished.then_some(CREATED);
            slot.outcome = charge.result.map(ResultKind::wire);
        }
        expected
    }
}

fn multi_request(index: usize) -> &'static str {
    ["multi-worker-first", "multi-worker-second"][index]
}

fn multi_database() -> Database {
    let mut manifest = manifest();
    let mut second = manifest.actions[0].as_publish().unwrap().clone();
    second.secret_name = "MODEL_SECOND_VALUE".into();
    manifest.actions.push(second.into());
    let database = Database::plan_manifest(manifest);
    let store = database.store.as_ref().unwrap();
    store.claim(&database.original.id, OWNER, CREATED).unwrap();
    store
        .approve(
            &database.original.id,
            OWNER,
            &database.original.manifest_digest,
            TaskApprovalMode::InsecureTest,
            CREATED,
        )
        .unwrap();
    database
}

fn multi_operation(store: &TaskStore, task: &TaskRecord, action: MultiAction) -> bool {
    let result = match action {
        MultiAction::Reserve(index) => store
            .reserve_slot(
                &task.id,
                OWNER,
                &task.slots[index].id,
                multi_request(index),
                CREATED,
            )
            .map(|_| ()),
        MultiAction::Dispatch(index) => store.authorize_dispatch(
            &task.id,
            OWNER,
            &task.slots[index].id,
            multi_request(index),
            CREATED,
        ),
        MultiAction::Complete(index, result) => store
            .finalize_slot(
                &task.id,
                OWNER,
                &task.slots[index].id,
                multi_request(index),
                result.wire(),
                CREATED,
            )
            .map(|_| ()),
        MultiAction::Revoke => store.revoke(&task.id, OWNER, CREATED).map(|_| ()),
        MultiAction::Reopen => panic!("reopen requires exclusive process ownership"),
    };
    match result {
        Ok(()) => true,
        Err(error) => {
            assert!(
                matches!(
                    error,
                    TaskStoreError::Revoked
                        | TaskStoreError::NotApproved
                        | TaskStoreError::SlotConsumed
                        | TaskStoreError::InvalidTransition
                ),
                "non-authority failure for {action:?}: {error:?}"
            );
            false
        }
    }
}

fn multi_apply(database: &mut Database, action: MultiAction) -> bool {
    if action == MultiAction::Reopen {
        drop(database.store.take());
        database.store = Some(TaskStore::open(&database.path).unwrap());
        true
    } else {
        multi_operation(database.store.as_ref().unwrap(), &database.original, action)
    }
}

fn permutations(actions: &[MultiAction]) -> Vec<Vec<MultiAction>> {
    if actions.is_empty() {
        return vec![Vec::new()];
    }
    let mut result = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        let mut remaining = actions.to_vec();
        remaining.remove(index);
        for mut suffix in permutations(&remaining) {
            suffix.insert(0, *action);
            result.push(suffix);
        }
    }
    result
}

#[test]
fn two_slot_reserve_finalize_revoke_restart_histories_match_reference() {
    use MultiAction::*;
    use ResultKind::{Accepted, Rejected, Unknown};
    // Four explicit outcome pairs; every interleaving preserves each worker's
    // reserve-before-complete program order. Revoke/reopen may occur anywhere.
    // This is a bounded history set, not a claim about all concurrent programs.
    let outcomes = [
        (Accepted, Accepted),
        (Accepted, Unknown),
        (Rejected, Accepted),
        (Unknown, Rejected),
    ];
    let mut histories = 0;
    let mut checks = 0;
    let mut observed_states = BTreeSet::new();
    let mut observed_charge_counts = BTreeSet::new();
    let mut recovered_unknown = false;
    for (first, second) in outcomes {
        let histories_for_pair = permutations(&[
            Reserve(0),
            Complete(0, first),
            Reserve(1),
            Complete(1, second),
            Revoke,
            Reopen,
        ])
        .into_iter()
        .filter(|history| {
            (0..2).all(|index| {
                history.iter().position(|a| *a == Reserve(index)).unwrap()
                    < history
                        .iter()
                        .position(|a| matches!(a, Complete(slot, _) if *slot == index))
                        .unwrap()
            })
        })
        .collect::<BTreeSet<_>>();
        assert_eq!(histories_for_pair.len(), 180);
        for history in histories_for_pair {
            let mut database = multi_database();
            let mut model = MultiModel::approved();
            assert_eq!(database.observe(), model.record(&database.original));
            checks += 1;
            for (index, &action) in history.iter().enumerate() {
                let before = model.clone();
                let expected = model.apply(action);
                assert_eq!(
                    multi_apply(&mut database, action),
                    expected,
                    "history prefix={:?}",
                    &history[..=index]
                );
                for slot in 0..2 {
                    assert!(!before.slots[slot].reserved || model.slots[slot].reserved);
                }
                assert_eq!(
                    database.observe(),
                    model.record(&database.original),
                    "history prefix={:?}",
                    &history[..=index]
                );
                observed_states.insert(model.authority);
                observed_charge_counts.insert(model.slots.iter().filter(|s| s.reserved).count());
                recovered_unknown |= model
                    .slots
                    .iter()
                    .any(|s| s.result == Some(ResultKind::Interrupted) && !s.finished);
                checks += 1;
            }
            // A second restart and every formerly charged or still-pending
            // slot remain closed; failed attempts preserve the complete row.
            let closed = database.observe();
            assert!(multi_apply(&mut database, Reopen));
            assert_eq!(database.observe(), closed);
            for slot in 0..2 {
                for attempt in [Reserve(slot), Dispatch(slot), Complete(slot, Accepted)] {
                    assert!(!multi_apply(&mut database, attempt));
                    assert_eq!(database.observe(), closed);
                }
            }
            histories += 1;
        }
    }
    assert_eq!((histories, checks), (720, 5040));
    assert_eq!(observed_charge_counts, BTreeSet::from([0, 1, 2]));
    assert_eq!(
        observed_states,
        BTreeSet::from([
            Authority::Claimed,
            Authority::Succeeded,
            Authority::Closed,
            Authority::Withdrawn,
        ])
    );
    assert!(recovered_unknown);
    println!(
        "TASK_MULTI_SLOT_HISTORY_COVERAGE {}",
        serde_json::json!({"slots": 2, "worker_programs": 2, "outcome_pairs": 4,
            "interleavings_per_pair": 180, "fresh_database_histories": histories,
            "persisted_prefix_comparisons": checks, "terminal_replay_comparisons": histories * 7,
            "provider_calls": 0})
    );
}

#[test]
fn concurrent_two_slot_effects_match_a_serial_history_and_remain_charged_on_restart() {
    use MultiAction::*;
    use ResultKind::{Accepted, Unknown};
    let mut runs = 0;
    for outcome in [Accepted, Unknown] {
        let operations = [Complete(0, outcome), Reserve(1), Revoke, Dispatch(0)];
        let serial_orders = permutations(&operations);
        assert_eq!(serial_orders.len(), 24);
        // Barrier races supplement deterministic interleavings. No assertion
        // depends on the OS choosing a particular order or covering all orders.
        for _ in 0..16 {
            let mut database = multi_database();
            let mut initial = MultiModel::approved();
            assert!(initial.apply(Reserve(0)));
            assert!(multi_apply(&mut database, Reserve(0)));
            let barrier = std::sync::Barrier::new(operations.len());
            let actual_results = std::thread::scope(|scope| {
                let store = database.store.as_ref().unwrap();
                let task = &database.original;
                let handles = operations
                    .iter()
                    .map(|&action| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            barrier.wait();
                            multi_operation(store, task, action)
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect::<Vec<_>>()
            });
            let committed = database.observe();
            let candidates = serial_orders
                .iter()
                .filter_map(|history| {
                    let mut model = initial.clone();
                    let mut results = [false; 4];
                    for &action in history {
                        let index = operations.iter().position(|a| *a == action).unwrap();
                        results[index] = model.apply(action);
                    }
                    (results.as_slice() == actual_results
                        && model.record(&database.original) == committed)
                        .then_some(model)
                })
                .collect::<Vec<_>>();
            assert!(
                !candidates.is_empty(),
                "concurrent results have no legal serial witness: {actual_results:?} {committed:?}"
            );
            assert_eq!(committed.state, TaskState::Revoked);
            assert!(multi_apply(&mut database, Reopen));
            let recovered = database.observe();
            for mut candidate in candidates {
                candidate.apply(Reopen);
                assert_eq!(recovered, candidate.record(&database.original));
            }
            for slot in 0..2 {
                assert!(!multi_apply(&mut database, Reserve(slot)));
                assert!(!multi_apply(&mut database, Dispatch(slot)));
                assert!(!multi_apply(&mut database, Complete(slot, Accepted)));
            }
            assert_eq!(database.observe(), recovered);
            runs += 1;
        }
    }
    assert_eq!(runs, 32);
    println!("TASK_CONCURRENT_HISTORY_RUNS {runs}");
}
