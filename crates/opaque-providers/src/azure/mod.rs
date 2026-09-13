//! Prepared Azure Key Vault metadata and write operations; raw values stay in resolvers.
pub mod client;
#[cfg(test)]
mod prepared_tests;
pub mod resolve;
use client::AzureKeyVaultClient;
use opaque_core::{
    audit::{AuditEvent, AuditEventKind, AuditSink},
    operation::OperationRequest,
    operation_handler::{OperationHandler, PreparedOperation},
    resolver::{BaseResolver, SecretResolver},
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
pub struct AzureHandler {
    audit: Arc<dyn AuditSink>,
    client: AzureKeyVaultClient,
}
impl std::fmt::Debug for AzureHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureHandler").finish_non_exhaustive()
    }
}
impl AzureHandler {
    /// The final argument is a broker-owned credential ref, never a raw secret.
    pub fn new(
        audit: Arc<dyn AuditSink>,
        base: &str,
        tenant: String,
        application: String,
        credential_ref: String,
    ) -> Result<Self, client::AzureApiError> {
        Ok(Self::from_client(
            audit,
            AzureKeyVaultClient::new(base, tenant, application, credential_ref)?,
        ))
    }
    pub fn from_client(audit: Arc<dyn AuditSink>, client: AzureKeyVaultClient) -> Self {
        Self { audit, client }
    }
}
#[derive(Serialize)]
struct Action {
    operation: String,
    name: Option<String>,
    version: Option<String>,
    value_ref: Option<String>,
    vault_url: String,
    auth: client::AuthBinding,
}
fn parse(request: &OperationRequest, client: &AzureKeyVaultClient) -> Result<Action, String> {
    let (required, optional): (&[&str], &[&str]) =
        match request.operation.as_str() {
            "azure.list_secrets" | "azure.list_keys" | "azure.list_certificates" => (&[], &[]),
            "azure.get_secret" => (&["name"], &["version"]),
            "azure.set_secret" => (&["name", "value_ref"], &[]),
            "azure.read_secret" | "azure.reveal_secret" => return Err(
                "raw secret reveal is disabled; use an azure: reference in an authorized consumer"
                    .into(),
            ),
            _ => return Err("unknown Azure operation".into()),
        };
    let params = request
        .params
        .as_object()
        .ok_or("parameters must be an object")?;
    if required
        .iter()
        .any(|key| !params.get(*key).is_some_and(serde_json::Value::is_string))
        || params.iter().any(|(key, value)| {
            (!required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
                || !value.is_string()
        })
    {
        return Err("exact Azure operation parameters required".into());
    }
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(n) = &name {
        client::validate_name(n).map_err(|e| e.to_string())?;
    }
    let version = params
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(v) = &version {
        client::validate_version(v).map_err(|e| e.to_string())?;
    }
    let value_ref = params
        .get("value_ref")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(v) = &value_ref {
        client::validate_ref(v)?;
    }
    Ok(Action {
        operation: request.operation.clone(),
        name,
        version,
        value_ref,
        vault_url: client.base_url().into(),
        auth: client.auth_binding().clone(),
    })
}
impl OperationHandler for AzureHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = parse(request, &self.client)?;
        let mut refs = action.auth.refs();
        if let Some(value) = &action.value_ref {
            refs.push(value.clone());
        }
        let mut target = HashMap::from([
            ("azure_vault_url".into(), action.vault_url.clone()),
            ("azure_tenant_id".into(), action.auth.tenant_id.clone()),
            ("azure_client_id".into(), action.auth.client_id.clone()),
        ]);
        if let Some(name) = &action.name {
            target.insert("name".into(), name.clone());
        }
        if let Some(version) = &action.version {
            target.insert("version".into(), version.clone());
        }
        if let Some(vault) = self.client.vault_name() {
            target.insert("vault".into(), vault.into());
        }
        let request_id = request.request_id;
        PreparedOperation::new(action, target, refs, move |action| async move {
            self.audit.emit(
                AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                    .with_request_id(request_id)
                    .with_operation(&action.operation),
            );
            let result = match action.operation.as_str() {
                "azure.list_secrets" => {
                    let rows = self
                        .client
                        .list_secrets()
                        .await
                        .map_err(|e| e.to_string())?;
                    let mut output = Vec::new();
                    for row in rows {
                        let name = self
                            .client
                            .resource_name(&row.id, "secrets")
                            .map_err(|e| e.to_string())?;
                        output.push(serde_json::json!({"name":name,"enabled":row.attributes.and_then(|a|a.enabled)}));
                    }
                    serde_json::json!({"secrets":output})
                }
                "azure.list_keys" => {
                    let rows = self.client.list_keys().await.map_err(|e| e.to_string())?;
                    let mut output = Vec::new();
                    for row in rows {
                        let name = self
                            .client
                            .resource_name(&row.kid, "keys")
                            .map_err(|e| e.to_string())?;
                        output.push(serde_json::json!({"name":name,"enabled":row.attributes.and_then(|a|a.enabled)}));
                    }
                    serde_json::json!({"keys":output})
                }
                "azure.list_certificates" => {
                    let rows = self
                        .client
                        .list_certificates()
                        .await
                        .map_err(|e| e.to_string())?;
                    let mut output = Vec::new();
                    for row in rows {
                        let name = self
                            .client
                            .resource_name(&row.id, "certificates")
                            .map_err(|e| e.to_string())?;
                        output.push(serde_json::json!({"name":name,"enabled":row.attributes.and_then(|a|a.enabled)}));
                    }
                    serde_json::json!({"certificates":output})
                }
                "azure.get_secret" => {
                    let secret = self
                        .client
                        .get_secret(action.name.as_deref().unwrap(), action.version.as_deref())
                        .await
                        .map_err(|e| e.to_string())?;
                    let name = self
                        .client
                        .resource_name(&secret.id, "secrets")
                        .map_err(|e| e.to_string())?;
                    if Some(name.as_str()) != action.name.as_deref() {
                        return Err("Azure returned a different secret".into());
                    }
                    serde_json::json!({"name":name,"enabled":secret.attributes.as_ref().and_then(|a|a.enabled),"metadata_only":true})
                }
                "azure.set_secret" => {
                    let value = BaseResolver::new()
                        .resolve(action.value_ref.as_deref().unwrap())
                        .map_err(|_| "Azure value reference unavailable")?;
                    let value = value.as_str().ok_or("Azure secret value must be UTF-8")?;
                    let secret = self
                        .client
                        .set_secret(action.name.as_deref().unwrap(), value)
                        .await
                        .map_err(|e| e.to_string())?;
                    let name = self
                        .client
                        .resource_name(&secret.id, "secrets")
                        .map_err(|e| e.to_string())?;
                    if Some(name.as_str()) != action.name.as_deref() {
                        return Err("Azure returned a different secret".into());
                    }
                    serde_json::json!({"name":name,"status":"written"})
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
    [("azure.list_secrets",vec![],"List Azure Key Vault secret metadata",false),
     ("azure.list_keys",vec![],"List Azure Key Vault key metadata",false),
     ("azure.list_certificates",vec![],"List Azure Key Vault certificate metadata",false),
     ("azure.get_secret",vec!["name"],"Read Azure secret metadata without disclosing its value",false),
     ("azure.set_secret",vec!["name","value_ref"],"Write a resolved value to Azure Key Vault",true)]
    .into_iter().map(|(name,required,description,write)|{
        let mut properties:serde_json::Map<String,serde_json::Value>=required.iter().map(|key|(key.to_string(),serde_json::json!({"type":"string","minLength":1,"maxLength":512}))).collect();
        if name=="azure.get_secret"{properties.insert("version".into(),serde_json::json!({"type":"string","minLength":1,"maxLength":128}));}
        OperationDef{name:name.into(),safety:OperationSafety::Safe,default_approval:if write{ApprovalRequirement::Always}else{ApprovalRequirement::FirstUse},default_factors:vec![ApprovalFactor::LocalBio],description:description.into(),params_schema:Some(serde_json::json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})),allowed_target_keys:vec!["name","version","vault","azure_vault_url","azure_tenant_id","azure_client_id"].into_iter().map(str::to_owned).collect(),secret_ref_param_keys:if write{vec!["value_ref".into()]}else{vec![]}}
    }).collect()
}
