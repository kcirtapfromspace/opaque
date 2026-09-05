//! Canonical workload observations produced by a trusted transport attestor.
//!
//! These types are not proof by themselves. The daemon must select an attestor
//! from its listener, never deserialize caller-provided values as authority.
//! Legacy client matching and approval fingerprints remain unchanged while
//! the workload context is introduced alongside them.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid workload selector or attestor identifier")]
pub struct InvalidSelector;

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// Stable namespace identifying the server-selected attestor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AttestorId(String);

impl AttestorId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AttestorId {
    type Error = InvalidSelector;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if valid_name(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidSelector)
        }
    }
}

impl From<AttestorId> for String {
    fn from(value: AttestorId) -> Self {
        value.0
    }
}

/// A namespaced observation rendered as `<source>:<key>:<value>`.
/// Values may contain colons (for example an image digest or executable path).
/// Ordering is by the source/key/value tuple, independent of insertion order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Selector {
    source: String,
    key: String,
    value: String,
}

impl Selector {
    pub fn new(source: &str, key: &str, value: &str) -> Result<Self, InvalidSelector> {
        if !valid_name(source)
            || !valid_name(key)
            || value.is_empty()
            || value.chars().any(char::is_control)
        {
            return Err(InvalidSelector);
        }
        Ok(Self {
            source: source.into(),
            key: key.into(),
            value: value.into(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}:{}", self.source, self.key, self.value)
    }
}

impl FromStr for Selector {
    type Err = InvalidSelector;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.splitn(3, ':');
        let source = parts.next().ok_or(InvalidSelector)?;
        let key = parts.next().ok_or(InvalidSelector)?;
        let value = parts.next().ok_or(InvalidSelector)?;
        Self::new(source, key, value)
    }
}

impl TryFrom<String> for Selector {
    type Error = InvalidSelector;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Selector> for String {
    fn from(value: Selector) -> Self {
        value.to_string()
    }
}

/// Achieved attestation strength, ordered from unavailable to strongest.
/// This is an attestor result, never a caller assertion or policy grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStrength {
    None,
    Weak,
    Medium,
    Strong,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub selectors: BTreeSet<Selector>,
    pub strength: AttestationStrength,
    pub source: AttestorId,
}

impl WorkloadIdentity {
    /// Failure drops every observation; partial identities cannot survive.
    pub fn unavailable(source: AttestorId) -> Self {
        Self {
            selectors: BTreeSet::new(),
            strength: AttestationStrength::None,
            source,
        }
    }

    pub fn is_attested(&self) -> bool {
        self.strength != AttestationStrength::None && !self.selectors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use super::*;

    #[test]
    fn canonical_sets_serialize_and_hash_identically() {
        let selectors = [
            "peercred:uid:501",
            "peercred:gid:20",
            "peercred:exe_path:/opt/a:b",
        ];
        let make = |values: Vec<&str>| WorkloadIdentity {
            selectors: values.into_iter().map(|v| v.parse().unwrap()).collect(),
            strength: AttestationStrength::Weak,
            source: "peercred".to_owned().try_into().unwrap(),
        };
        let first = make(selectors.to_vec());
        let second = make(selectors.into_iter().rev().chain([selectors[0]]).collect());
        assert_eq!(first, second);
        let hash = |value: &WorkloadIdentity| {
            let mut hasher = DefaultHasher::new();
            value.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash(&first), hash(&second));
        let json = serde_json::to_string(&first).unwrap();
        assert_eq!(json, serde_json::to_string(&second).unwrap());
        assert_eq!(first, serde_json::from_str(&json).unwrap());
        assert_eq!(
            first
                .selectors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "peercred:exe_path:/opt/a:b",
                "peercred:gid:20",
                "peercred:uid:501"
            ]
        );
    }

    #[test]
    fn malformed_selectors_and_unknown_strength_are_rejected() {
        for value in [
            "uid:501",
            ":uid:501",
            "peercred::501",
            "peercred:uid:",
            "PEERCRED:uid:501",
            "peercred:uid:5\n01",
        ] {
            assert!(value.parse::<Selector>().is_err(), "accepted {value:?}");
            assert!(serde_json::from_value::<Selector>(serde_json::json!(value)).is_err());
        }
        assert!(serde_json::from_str::<AttestationStrength>("\"hardware\"").is_err());
        assert!(serde_json::from_str::<AttestorId>("\"peercred:spoof\"").is_err());
    }

    #[test]
    fn strength_order_and_unavailable_identity_are_explicit() {
        use AttestationStrength::*;
        assert!(None < Weak && Weak < Medium && Medium < Strong);
        let identity = WorkloadIdentity::unavailable("peercred".to_owned().try_into().unwrap());
        assert_eq!(identity.strength, None);
        assert!(identity.selectors.is_empty());
        assert!(!identity.is_attested());
    }
}
