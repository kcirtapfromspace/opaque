//! Tenant identity is provenance, not a substitute for an isolation boundary.
//!
//! A dedicated broker derives this binding from trusted startup configuration
//! and its private persisted state. Deserializing a binding supplied by a
//! client never authenticates the client or grants access to that tenant.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::PrincipalId;

/// An opaque namespace chosen by the operator, never a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, TenantError> {
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)
            })
            || !value.as_bytes()[0].is_ascii_alphanumeric()
            || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        {
            return Err(TenantError::InvalidTenantId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<TenantId> for String {
    fn from(value: TenantId) -> Self {
        value.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A tenant and one immutable broker state lineage. Separate brokers serving
/// the same tenant still have different bindings and cannot reuse authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantBinding {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub broker_id: Uuid,
}

impl TenantBinding {
    pub fn new(tenant_id: TenantId, broker_id: Uuid) -> Result<Self, TenantError> {
        let binding = Self {
            schema_version: 1,
            tenant_id,
            broker_id,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), TenantError> {
        if self.schema_version != 1 || self.broker_id.is_nil() {
            return Err(TenantError::InvalidBinding);
        }
        TenantId::parse(self.tenant_id.as_str())?;
        Ok(())
    }

    /// Compare against the broker's trusted binding before reading a receipt,
    /// resolving a credential profile, or dispatching an approved action.
    pub fn require_same(&self, offered: &Self) -> Result<(), TenantError> {
        self.validate()?;
        offered.validate()?;
        if self != offered {
            return Err(TenantError::WrongBoundary);
        }
        Ok(())
    }

    /// The uid and principal must already come from broker-authenticated
    /// context. A session restart does not alter this durable owner scope.
    pub fn owner_key(&self, uid: u32, principal: Option<&PrincipalId>) -> String {
        let prefix = format!(
            "tenant:{}:broker:{}:uid:{uid}",
            self.tenant_id, self.broker_id
        );
        match principal {
            Some(principal) => format!("{prefix}:sub:{}", principal.as_str()),
            None => prefix,
        }
    }

    /// Include this exact text in the full trusted review so its content hash
    /// and signed decision cover both tenant and broker state lineage.
    pub fn approval_context(&self) -> String {
        format!(
            "Tenant: {}\nTenant broker: {}\n",
            self.tenant_id, self.broker_id
        )
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TenantError {
    #[error(
        "tenant ID must be 1–64 lowercase ASCII letters, digits, hyphens or underscores with alphanumeric ends"
    )]
    InvalidTenantId,
    #[error("invalid tenant broker binding")]
    InvalidBinding,
    #[error("resource belongs to a different tenant or broker")]
    WrongBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(id: &str) -> TenantBinding {
        TenantBinding::new(TenantId::parse(id).unwrap(), Uuid::new_v4()).unwrap()
    }

    #[test]
    fn tenant_ids_are_canonical_and_cannot_be_paths_or_display_labels() {
        for valid in ["opaque", "tenant-01", "tenant_app", "0", "a"] {
            assert_eq!(TenantId::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "",
            "OPAQUE",
            "../opaque",
            "opaque/other",
            ".",
            "a.b",
            "-a",
            "a_",
            "a:b",
            "a b",
            "ä",
            "a\n",
        ] {
            assert!(TenantId::parse(invalid).is_err(), "accepted {invalid:?}");
            assert!(serde_json::from_value::<TenantId>(serde_json::json!(invalid)).is_err());
        }
        assert!(TenantId::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn tenant_and_broker_are_both_required_for_authority() {
        let first = binding("tenant-a");
        let other_tenant =
            TenantBinding::new(TenantId::parse("tenant-b").unwrap(), first.broker_id).unwrap();
        let other_broker = binding("tenant-a");
        assert!(first.require_same(&first).is_ok());
        assert_eq!(
            first.require_same(&other_tenant),
            Err(TenantError::WrongBoundary)
        );
        assert_eq!(
            first.require_same(&other_broker),
            Err(TenantError::WrongBoundary)
        );
        assert_ne!(
            first.owner_key(1000, None),
            other_tenant.owner_key(1000, None)
        );
        assert_ne!(
            first.owner_key(1000, None),
            other_broker.owner_key(1000, None)
        );
        assert_ne!(first.approval_context(), other_tenant.approval_context());
        assert_ne!(first.approval_context(), other_broker.approval_context());
    }

    #[test]
    fn malformed_binding_and_unknown_authority_fields_fail_closed() {
        let first = binding("tenant-a");
        let mut invalid = first.clone();
        invalid.schema_version = 2;
        assert!(first.require_same(&invalid).is_err());
        invalid.schema_version = 1;
        invalid.broker_id = Uuid::nil();
        assert!(invalid.validate().is_err());
        let mut value = serde_json::to_value(&first).unwrap();
        value["is_admin"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TenantBinding>(value).is_err());
    }
}
