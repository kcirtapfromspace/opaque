//! Broker-prepared Google Secret Manager operations. Secret values stay in resolvers.
pub mod client;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod prepared_tests;
pub mod resolve;
use client::GcpSecretManagerClient;
use opaque_core::{
    audit::{AuditEvent, AuditEventKind, AuditSink},
    operation::OperationRequest,
    operation_handler::{OperationHandler, PreparedOperation},
    resolver::{BaseResolver, SecretResolver},
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};

pub struct GcpHandler {
    audit: Arc<dyn AuditSink>,
    client: GcpSecretManagerClient,
}
impl std::fmt::Debug for GcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpHandler").finish_non_exhaustive()
    }
}
impl GcpHandler {
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Result<Self, client::GcpApiError> {
        Ok(Self::from_client(
            audit,
            GcpSecretManagerClient::new(base_url)?,
        ))
    }
    pub fn from_client(audit: Arc<dyn AuditSink>, client: GcpSecretManagerClient) -> Self {
        Self { audit, client }
    }
}
#[derive(Serialize)]
struct Action {
    operation: String,
    project: String,
    secret_id: Option<String>,
    value_ref: Option<String>,
    api_url: String,
    token_endpoint: String,
    auth: client::AuthBinding,
}
fn parse(request: &OperationRequest, client: &GcpSecretManagerClient) -> Result<Action, String> {
    let fields: &[&str] = match request.operation.as_str() {
        "gcp.list_secrets" => &["project"],
        "gcp.get_secret" | "gcp.create_secret" => &["project", "secret_id"],
        "gcp.add_secret_version" => &["project", "secret_id", "value_ref"],
        "gcp.access_secret_version" => {
            return Err(
                "raw secret reveal is disabled; use a gcp: reference in an authorized consumer"
                    .into(),
            );
        }
        _ => return Err("unknown GCP operation".into()),
    };
    let params = request
        .params
        .as_object()
        .ok_or("parameters must be an object")?;
    if params.len() != fields.len()
        || fields
            .iter()
            .any(|name| !params.get(*name).is_some_and(serde_json::Value::is_string))
    {
        return Err("exact GCP operation parameters required".into());
    }
    let project = params["project"].as_str().unwrap().to_owned();
    client::validate_project(&project).map_err(|e| e.to_string())?;
    let secret_id = params
        .get("secret_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(secret) = &secret_id {
        client::validate_secret(secret).map_err(|e| e.to_string())?;
    }
    let value_ref = params
        .get("value_ref")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(value) = &value_ref {
        client::validate_ref(value)?;
    }
    Ok(Action {
        operation: request.operation.clone(),
        project,
        secret_id,
        value_ref,
        api_url: client.base_url().into(),
        token_endpoint: client.token_endpoint().into(),
        auth: client.auth_binding().clone(),
    })
}
fn metadata(secret: client::GcpSecret) -> Result<serde_json::Value, String> {
    resource_name(&secret.name, false)?;
    if let Some(time) = &secret.create_time {
        chrono::DateTime::parse_from_rfc3339(time).map_err(|_| "invalid GCP metadata time")?;
    }
    Ok(serde_json::json!({"name":secret.name,"create_time":secret.create_time}))
}
fn resource_name(value: &str, version: bool) -> Result<(), String> {
    let fields: Vec<_> = value.split('/').collect();
    if fields.len() != if version { 6 } else { 4 }
        || fields[0] != "projects"
        || fields[2] != "secrets"
    {
        return Err("invalid GCP resource metadata".into());
    }
    client::validate_project(fields[1]).map_err(|e| e.to_string())?;
    client::validate_secret(fields[3]).map_err(|e| e.to_string())?;
    if version && (fields[4] != "versions" || client::validate_version(fields[5]).is_err()) {
        return Err("invalid GCP version metadata".into());
    }
    Ok(())
}
impl OperationHandler for GcpHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = parse(request, &self.client)?;
        let mut refs = action.auth.refs();
        if let Some(value) = &action.value_ref {
            refs.push(value.clone());
        }
        let mut target = HashMap::from([
            ("project".into(), action.project.clone()),
            ("gcp_api_url".into(), action.api_url.clone()),
            ("gcp_token_endpoint".into(), action.token_endpoint.clone()),
        ]);
        if let Some(secret) = &action.secret_id {
            target.insert("secret_id".into(), secret.clone());
        }
        let request_id = request.request_id;
        PreparedOperation::new(action, target, refs, move |action| async move {
            self.audit.emit(
                AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                    .with_request_id(request_id)
                    .with_operation(&action.operation),
            );
            // Resolving these exact refs is deferred until after authorization.
            let value = action
                .value_ref
                .as_ref()
                .map(|r| {
                    BaseResolver::new()
                        .resolve(r)
                        .map_err(|_| "GCP value reference unavailable".to_owned())
                })
                .transpose()?;
            if value.as_ref().is_some_and(|v| v.as_bytes().len() > 65536) {
                return Err("GCP secret exceeds 64 KiB".into());
            }
            let token = self
                .client
                .get_access_token()
                .await
                .map_err(|e| e.to_string())?;
            let result = match action.operation.as_str() {
                "gcp.list_secrets" => {
                    let secrets = self
                        .client
                        .list_secrets(&token, &action.project)
                        .await
                        .map_err(|e| e.to_string())?;
                    let mut names = Vec::new();
                    for secret in secrets {
                        resource_name(&secret.name, false)?;
                        names.push(
                            serde_json::json!({"name":secret.name.rsplit('/').next().unwrap()}),
                        );
                    }
                    serde_json::json!({"project":action.project,"secrets":names})
                }
                "gcp.get_secret" => metadata(
                    self.client
                        .get_secret(
                            &token,
                            &action.project,
                            action.secret_id.as_deref().unwrap(),
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                )?,
                "gcp.create_secret" => metadata(
                    self.client
                        .create_secret(
                            &token,
                            &action.project,
                            action.secret_id.as_deref().unwrap(),
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                )?,
                "gcp.add_secret_version" => {
                    let version = self
                        .client
                        .add_secret_version(
                            &token,
                            &action.project,
                            action.secret_id.as_deref().unwrap(),
                            value.as_ref().unwrap().as_bytes(),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    resource_name(&version.name, true)?;
                    if version.state.as_deref().is_some_and(|s| {
                        !matches!(
                            s,
                            "ENABLED" | "DISABLED" | "DESTROYED" | "STATE_UNSPECIFIED"
                        )
                    }) {
                        return Err("invalid GCP version state".into());
                    }
                    serde_json::json!({"version":version.name,"state":version.state})
                }
                _ => unreachable!("validated operation"),
            };
            self.audit.emit(
                AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                    .with_request_id(request_id)
                    .with_operation(&action.operation)
                    .with_outcome("ok"),
            );
            Ok(result)
        })
    }
}

/// Definitions for the supported, non-revealing broker operations.
pub fn operations() -> Vec<opaque_core::operation::OperationDef> {
    use opaque_core::operation::{
        ApprovalFactor, ApprovalRequirement, OperationDef, OperationSafety,
    };
    [("gcp.list_secrets",vec!["project"],"List Google Secret Manager names",false),
     ("gcp.get_secret",vec!["project","secret_id"],"Read Google Secret Manager metadata",false),
     ("gcp.create_secret",vec!["project","secret_id"],"Create a Google Secret Manager container with automatic replication",true),
     ("gcp.add_secret_version",vec!["project","secret_id","value_ref"],"Write a resolved value as a new Google secret version",true)]
    .into_iter().map(|(name,required,description,write)|{
        let properties:serde_json::Map<String,serde_json::Value>=required.iter().map(|key|(key.to_string(),if *key == "project" { serde_json::json!({"type":"string","pattern":"^[1-9][0-9]{0,19}$","maxLength":20,"description":"Canonical numeric Google Cloud project number"}) } else { serde_json::json!({"type":"string","minLength":1,"maxLength":512}) })).collect();
        OperationDef{name:name.into(),safety:OperationSafety::Safe,default_approval:if write{ApprovalRequirement::Always}else{ApprovalRequirement::FirstUse},default_factors:vec![ApprovalFactor::LocalBio],description:description.into(),params_schema:Some(serde_json::json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})),allowed_target_keys:vec!["project","secret_id","gcp_api_url","gcp_token_endpoint"].into_iter().map(str::to_owned).collect(),secret_ref_param_keys:if required.contains(&"value_ref"){vec!["value_ref".into()]}else{vec![]}}
    }).collect()
}
