//! Fixture-only organization simulator. Organization membership never supplies
//! a customer metric scope. Each persona also has a distinct admitted OAuth
//! subject/client; the runtime keeps its cookies out of the visitor browser.
use crate::{
    auth::{AuthConfig, VerifiedAccess},
    experience::credit_request_denial,
};
use opaque_core::sanitize::Sanitizer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use uuid::Uuid;

pub const ACTIVITY_SCOPE: &str = "organization:activity:read";
const RETENTION_SECS: i64 = 900;
const MAX_RECORDS: usize = 100;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Persona {
    CustomerAnalyst,
    Engineer,
    Support,
}
impl Persona {
    pub fn label(self) -> &'static str {
        match self {
            Self::CustomerAnalyst => "Portfolio analyst",
            Self::Engineer => "Product engineer",
            Self::Support => "Customer support",
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub subject: String,
    pub persona_id: Persona,
    pub oauth_client_id: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCustomer {
    pub id: String,
    pub display_name: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationConfig {
    pub id: String,
    pub display_name: String,
    pub members: Vec<Member>,
    #[serde(default)]
    pub other_customer: Option<DirectoryCustomer>,
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}
impl OrganizationConfig {
    pub fn foreign_customer_requested(&self, message: &str) -> bool {
        let Some(customer) = &self.other_customer else {
            return false;
        };
        let lower = message.to_lowercase();
        let words = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let name = customer.display_name.to_lowercase();
        let brand = name
            .split(|c: char| !c.is_alphanumeric())
            .find(|s| s.len() >= 4);
        lower.contains(&customer.id.to_lowercase())
            || lower.contains(&name)
            || brand.is_some_and(|brand| words.contains(&brand))
    }
    pub fn validate(&self, auth: &AuthConfig, tenant: &str) -> Result<(), String> {
        if !identifier(&self.id)
            || !text(&self.display_name, 120)
            || self.members.len() != 3
            || auth.admissions.len() != 3
        {
            return Err("organization demo needs three distinct configured identities".into());
        }
        let mut subjects = BTreeSet::new();
        let mut clients = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for member in &self.members {
            let admission = auth
                .admissions
                .iter()
                .find(|a| a.subject == member.subject && a.tenant_id.as_str() == tenant)
                .ok_or("organization member is not admitted to the configured customer")?;
            if !identifier(&member.subject)
                || !identifier(&member.oauth_client_id)
                || admission.client_id != member.oauth_client_id
                || !subjects.insert(&member.subject)
                || !clients.insert(&member.oauth_client_id)
                || !roles.insert(member.persona_id.label())
                || !admission.scopes.contains(ACTIVITY_SCOPE)
                || (member.persona_id == Persona::Engineer && admission.scopes.len() != 1)
                || (member.persona_id != Persona::Engineer
                    && !admission.scopes.contains("metrics:read"))
            {
                return Err("organization persona admission has invalid identity or scopes".into());
            }
        }
        if self
            .other_customer
            .as_ref()
            .is_some_and(|c| !identifier(&c.id) || c.id == tenant || !text(&c.display_name, 120))
        {
            return Err("organization directory entry is invalid".into());
        }
        Ok(())
    }
    pub fn member(&self, access: &VerifiedAccess) -> Result<&Member, String> {
        self.members
            .iter()
            .find(|m| m.subject == access.subject() && m.oauth_client_id == access.client_id())
            .ok_or_else(|| "This OAuth identity is not a member of the demo organization.".into())
    }
    pub fn persona(&self, persona: Persona) -> &Member {
        self.members
            .iter()
            .find(|m| m.persona_id == persona)
            .expect("validated persona configuration")
    }
}

#[derive(Clone, Serialize)]
pub struct SupportCase {
    pub case_id: String,
    pub subject: String,
    pub tenant_id: String,
    pub reason: String,
    pub expires_at: i64,
    pub generation: u64,
    #[serde(skip)]
    jti: String,
}
#[derive(Clone)]
struct Activity {
    id: String,
    at: i64,
    subject: String,
    jti: String,
    persona: Persona,
    kind: &'static str,
    model: String,
    question_sha256: Option<String>,
    question_bytes: usize,
    question_text: Option<String>,
    tool: Option<&'static str>,
    metrics: Vec<String>,
    window_secs: Option<u32>,
    query: Option<Value>,
    tool_calls: u32,
    outcome: &'static str,
    source_accessed: Option<bool>,
    reason_code: Option<String>,
}
pub struct OrganizationState {
    pub generation: u64,
    pub active: Persona,
    active_jti: Option<String>,
    pub support_case: Option<SupportCase>,
    sharing_owner: Option<String>,
    records: VecDeque<Activity>,
    controls: u32,
}
impl Default for OrganizationState {
    fn default() -> Self {
        Self {
            generation: 1,
            active: Persona::CustomerAnalyst,
            active_jti: None,
            support_case: None,
            sharing_owner: None,
            records: VecDeque::new(),
            controls: 0,
        }
    }
}
impl OrganizationState {
    fn charge_control(&mut self) {
        self.controls += 1;
        if self.controls >= 120 {
            self.sharing_owner = None;
            for record in &mut self.records {
                record.question_text = None;
            }
        }
    }
    pub fn snapshot(
        &self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
    ) -> Result<u64, String> {
        let member = config.member(access)?;
        if member.persona_id != self.active
            || self
                .active_jti
                .as_ref()
                .is_some_and(|jti| jti != access.jti())
        {
            return Err("This demo identity is not the active persona.".into());
        }
        Ok(self.generation)
    }
    pub fn check_data(
        &self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        generation: u64,
        now: i64,
    ) -> Result<(), String> {
        if self.snapshot(config, access)? != generation {
            return Err("The demo persona changed; this request has stopped.".into());
        }
        match self.active {
            Persona::Engineer => Err("Organization activity access does not grant customer metric access. The engineer can inspect activity metadata only.".into()),
            Persona::Support if !self.support_case.as_ref().is_some_and(|case| case.subject == access.subject()
                && case.jti == access.jti() && case.tenant_id == access.tenant_id() && case.generation == generation
                && case.expires_at > now) => Err("A current support case for this assigned customer is required. Select support and provide a reason to start a new five-minute case.".into()),
            _ => Ok(()),
        }
    }
    pub fn activate(
        &mut self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        persona: Persona,
        reason: Option<&str>,
        now: i64,
        audit: impl FnOnce(&Value) -> Result<(), String>,
    ) -> Result<(), String> {
        if config.member(access)?.persona_id != persona {
            return Err(
                "The selected persona does not match the authenticated OAuth subject.".into(),
            );
        }
        if self.controls >= 120 {
            return Err("This demo has reached its organization control limit.".into());
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("Persona generation exhausted")?;
        let support_case = if persona == Persona::Support {
            let reason = reason.filter(|r| text(r, 240) && r.trim().chars().count() >= 8).ok_or("Support requires a reason of at most 240 bytes; do not include borrower information.")?;
            if Sanitizer::new().scrub_error(reason) != reason
                || credit_request_denial(reason).is_some()
            {
                return Err(
                    "Use a support purpose without secrets or borrower information.".into(),
                );
            }
            Some(SupportCase {
                case_id: Uuid::new_v4().to_string(),
                subject: access.subject().into(),
                tenant_id: access.tenant_id().into(),
                reason: reason.into(),
                expires_at: (now + 300).min(access.expires_at()),
                generation,
                jti: access.jti().into(),
            })
        } else {
            if reason.is_some() {
                return Err("A support reason is accepted only for the support persona.".into());
            }
            None
        };
        audit(
            &json!({"operation":"organization.persona.activate","persona_id":persona,"generation":generation,"support_case":support_case}),
        )?;
        self.charge_control();
        self.generation = generation;
        self.active = persona;
        self.active_jti = Some(access.jti().into());
        self.support_case = support_case;
        Ok(())
    }
    pub fn set_sharing(
        &mut self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        enabled: bool,
        audit: impl FnOnce(&Value) -> Result<(), String>,
    ) -> Result<(), String> {
        self.snapshot(config, access)?;
        if self.active != Persona::CustomerAnalyst {
            return Err("Only the customer analyst can change question-sharing consent.".into());
        }
        if self.controls >= 120 && enabled {
            return Err("This demo has reached its organization control limit.".into());
        }
        // Consent can always be withdrawn. Repeated withdrawal after it is
        // already off creates neither audit records nor additional authority.
        if !enabled && self.sharing_owner.is_none() {
            return Ok(());
        }
        audit(&json!({"operation":"organization.question_sharing","enabled":enabled}))?;
        self.sharing_owner = enabled.then(|| access.jti().to_owned());
        if !enabled {
            for record in &mut self.records {
                record.question_text = None;
            }
        }
        self.charge_control();
        Ok(())
    }
    pub fn session(
        &self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        customer: &str,
        now: i64,
    ) -> Result<Value, String> {
        let member = config.member(access)?;
        let allowed = self
            .check_data(config, access, self.generation, now)
            .is_ok()
            && access.require_scope("metrics:read").is_ok();
        let mut directory = vec![
            json!({"id":access.tenant_id(),"display_name":customer,"relationship":"assigned_customer","data_access":allowed}),
        ];
        if let Some(other) = &config.other_customer {
            directory.push(json!({"id":other.id,"display_name":other.display_name,"relationship":"directory_only","data_access":false}));
        }
        Ok(
            json!({"id":config.id,"display_name":config.display_name,"simulation":true,"can_query":allowed,"can_chat":allowed&&access.require_scope("metrics:explain").is_ok(),
            "membership":{"subject":access.subject(),"persona_id":member.persona_id,"label":member.persona_id.label()},
            "active_persona_id":self.active,"generation":self.generation,
            "personas":config.members.iter().map(|m|json!({"id":m.persona_id,"label":m.persona_id.label()})).collect::<Vec<_>>(),
            "data_entitlement":{"tenant_id":access.tenant_id(),"display_name":customer,"allowed":allowed,"access":"read_only_aggregates","source":"explicit_customer_scope","requires_support_case":member.persona_id==Persona::Support},
            "content_visibility":{"sharing_enabled":self.sharing_owner.is_some(),"can_change":member.persona_id==Persona::CustomerAnalyst&&self.snapshot(config,access).is_ok(),"notice":"Question text is hidden by default. Sharing applies only to subsequent accepted questions for this demo and does not guarantee removal of personal information. Turning sharing off clears stored text.","retention_seconds":RETENTION_SECS},
            "support_case":self.support_case,"customers":directory,
            "activity_scope":"this_lease_only","activity_limit":MAX_RECORDS}),
        )
    }
    pub fn begin(
        &mut self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        kind: &'static str,
        model: String,
        question: Option<&str>,
        now: i64,
    ) -> Option<String> {
        let persona = config.member(access).ok()?.persona_id;
        self.records
            .retain(|record| now - record.at < RETENTION_SECS);
        while self.records.len() >= MAX_RECORDS {
            self.records.pop_front();
        }
        let id = Uuid::new_v4().to_string();
        let accepted = question.filter(|q| {
            credit_request_denial(q).is_none()
                && Sanitizer::new().scrub_error(q) == *q
                && q.len() <= 2000
                && !q
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        });
        let shared = accepted.filter(|_| {
            persona == Persona::CustomerAnalyst
                && self.sharing_owner.as_deref() == Some(access.jti())
        });
        self.records.push_back(Activity {
            id: id.clone(),
            at: now,
            subject: access.subject().into(),
            jti: access.jti().into(),
            persona,
            kind,
            model,
            question_sha256: question.map(|q| format!("{:x}", Sha256::digest(q.as_bytes()))),
            question_bytes: question.map_or(0, str::len),
            question_text: shared.map(str::to_owned),
            tool: None,
            metrics: Vec::new(),
            window_secs: None,
            query: None,
            tool_calls: 0,
            outcome: "started",
            source_accessed: Some(false),
            reason_code: None,
        });
        Some(id)
    }
    pub fn portfolio_tool(&mut self, id: &str, query: &crate::portfolio::PortfolioQuery) {
        self.tool(
            id,
            &query
                .measures
                .iter()
                .map(|m| m.id().into())
                .collect::<Vec<_>>(),
            query.window_secs,
        );
        if let Some(record) = self.records.iter_mut().find(|record| record.id == id) {
            record.tool = Some(crate::portfolio::TOOL);
            record.query = serde_json::to_value(query).ok();
        }
    }
    pub fn tool(&mut self, id: &str, metrics: &[String], window: u32) {
        if let Some(record) = self.records.iter_mut().find(|r| r.id == id) {
            record.tool = Some("opaque_metrics_query");
            record.metrics = metrics.to_vec();
            record.window_secs = Some(window);
            record.tool_calls = record.tool_calls.saturating_add(1);
            if record.source_accessed != Some(true) {
                record.source_accessed = None;
            }
        }
    }
    pub fn finish(
        &mut self,
        id: &str,
        outcome: &'static str,
        source_accessed: Option<bool>,
        reason: Option<&str>,
    ) {
        if let Some(record) = self.records.iter_mut().find(|r| r.id == id) {
            if record.outcome != "denied" || outcome != "failed" {
                record.outcome = outcome;
            }
            if record.source_accessed != Some(true) && source_accessed.is_some() {
                record.source_accessed = source_accessed;
            }
            if reason.is_some() {
                record.reason_code = reason.map(str::to_owned);
            }
            if outcome == "denied" {
                record.question_text = None;
            }
        }
    }
    pub fn activity(
        &mut self,
        config: &OrganizationConfig,
        access: &VerifiedAccess,
        customer: &str,
        now: i64,
    ) -> Result<Value, String> {
        self.snapshot(config, access)?;
        access
            .require_scope(ACTIVITY_SCOPE)
            .map_err(|e| e.to_string())?;
        if self.active == Persona::Support {
            self.check_data(config, access, self.generation, now)?;
        }
        self.records
            .retain(|record| now - record.at < RETENTION_SECS);
        let records=self.records.iter().rev().filter(|r|self.active!=Persona::CustomerAnalyst||r.jti==access.jti()).map(|r|json!({
            "request_id":r.id,"at":r.at,"kind":r.kind,"subject":r.subject,"persona_id":r.persona,"tenant_id":access.tenant_id(),"model":r.model,
            "question_sha256":r.question_sha256,"question_bytes":r.question_bytes,"question_text":r.question_text,
            "question_visibility":if r.question_text.is_some(){"shared_by_customer"}else{"hidden"},
            "tool":r.tool,"query":r.query,"metrics":r.metrics,"window_secs":r.window_secs,"tool_calls":r.tool_calls,
            "outcome":r.outcome,"source_accessed":r.source_accessed,"reason_code":r.reason_code})).collect::<Vec<_>>();
        Ok(
            json!({"organization":self.session(config,access,customer,now)?,"records":records,"retention_seconds":RETENTION_SECS,"scope":"this_lease_only"}),
        )
    }
}
