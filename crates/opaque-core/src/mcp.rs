//! Versioned third-party MCP admission contract shared by adapter and broker.
//!
//! The registry is administrator input, not a discovered server catalog. A
//! prepared call has passed configuration/schema checks only: the daemon
//! must also bind a verified principal, evaluate policy, obtain approval,
//! reserve an attempt durably, and enforce transport and credential custody.
//! There is deliberately no network client or authorization token here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const MAX_REGISTRY_BYTES: usize = 1024 * 1024;
pub const MAX_CALL_BYTES: usize = 64 * 1024;
pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const PREPARED_CONTRACT_VERSION: u32 = 2;
fn protocol_version() -> String {
    PROTOCOL_VERSION.into()
}
const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_SCHEMA_NODES: usize = 1024;

/// Fixed errors never interpolate registry material or submitted arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    InputTooLarge,
    InvalidRegistry,
    InvalidEndpoint,
    InvalidSchema,
    InvalidCall,
    UnknownRoute,
    ArgumentsRejected,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InputTooLarge => "contract input exceeds its byte limit",
            Self::InvalidRegistry => "invalid gateway registry",
            Self::InvalidEndpoint => "invalid pinned HTTPS endpoint",
            Self::InvalidSchema => "unsupported or unbounded input schema",
            Self::InvalidCall => "invalid gateway call envelope",
            Self::UnknownRoute => "gateway route is not registered",
            Self::ArgumentsRejected => "arguments do not match the pinned input schema",
        })
    }
}

impl std::error::Error for ContractError {}

/// HTTPS only, port 443, exact host/path. No credentials, query, fragment,
/// redirects, scheme selection or agent-supplied address can be expressed.
/// Syntax validation is not DNS/SSRF enforcement; transport must supply that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    /// Raw upstream bodies (including errors) must never reach the agent.
    Withhold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default = "protocol_version")]
    pub protocol_version: String,
    pub alias: String,
    pub server_id: String,
    pub endpoint: Endpoint,
    pub tool: String,
    /// Administrator-defined opaque lookup key, never a bearer or secret ref.
    /// The daemon maps this key to its own credential store.
    pub credential_binding: String,
    pub input_schema: Value,
    pub output_policy: OutputPolicy,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryDocument {
    pub version: u32,
    pub routes: Vec<Route>,
}

struct ValidatedRoute {
    route: Route,
    validator: jsonschema::Validator,
}

/// Immutable validated administrator configuration. Loading does not establish
/// its provenance; the daemon must verify signed-bundle custody first.
pub struct Registry {
    routes: BTreeMap<String, ValidatedRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    route: String,
    arguments: Map<String, Value>,
}

/// An immutable preparation snapshot, NOT evidence of authorization or dispatch.
/// Debug output withholds all argument values and credential configuration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedCall {
    route: Route,
    arguments: Map<String, Value>,
    digest: String,
}

impl fmt::Debug for PreparedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCall")
            .field("route", &self.route.alias)
            .field("action_digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl PreparedCall {
    pub fn route(&self) -> &Route {
        &self.route
    }

    /// Sensitive caller input for future typed dispatch; never log this map.
    pub fn arguments(&self) -> &Map<String, Value> {
        &self.arguments
    }

    /// Lowercase SHA-256 of a domain-separated, recursively key-sorted JSON
    /// snapshot. This is a preparation digest, not a signature or task grant.
    pub fn action_digest(&self) -> &str {
        &self.digest
    }
}

impl Registry {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(ContractError::InputTooLarge);
        }
        let document: RegistryDocument =
            serde_json::from_slice(bytes).map_err(|_| ContractError::InvalidRegistry)?;
        if document.version != 1 || document.routes.is_empty() || document.routes.len() > 128 {
            return Err(ContractError::InvalidRegistry);
        }
        let mut routes = BTreeMap::new();
        for route in document.routes {
            if route.protocol_version != PROTOCOL_VERSION
                || !identifier(&route.alias)
                || !identifier(&route.server_id)
                || !identifier(&route.tool)
                || !identifier(&route.credential_binding)
                || !(1..=MAX_CALL_BYTES).contains(&route.max_request_bytes)
                || !(1..=256 * 1024).contains(&route.max_response_bytes)
                || !(1..=120_000).contains(&route.timeout_ms)
                || routes.contains_key(&route.alias)
            {
                return Err(ContractError::InvalidRegistry);
            }
            validate_endpoint(&route.endpoint)?;
            let mut nodes = 0;
            validate_schema(&route.input_schema, 0, &mut nodes)?;
            if route.input_schema["type"] != "object" {
                return Err(ContractError::InvalidSchema);
            }
            // The admitted schema subset contains no references or regexes.
            // Compilation cannot resolve URLs, files or external schemas.
            let validator = jsonschema::validator_for(&route.input_schema)
                .map_err(|_| ContractError::InvalidSchema)?;
            routes.insert(route.alias.clone(), ValidatedRoute { route, validator });
        }
        Ok(Self { routes })
    }

    pub fn from_document(document: &RegistryDocument) -> Result<Self, ContractError> {
        Self::from_json(&serde_json::to_vec(document).map_err(|_| ContractError::InvalidRegistry)?)
    }

    pub fn routes(&self) -> Vec<Route> {
        self.routes
            .values()
            .map(|value| value.route.clone())
            .collect()
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Validate the agent envelope and freeze the exact administrator route and
    /// arguments together. There are no endpoint/header/approval override fields.
    pub fn prepare_json(&self, bytes: &[u8]) -> Result<PreparedCall, ContractError> {
        if bytes.len() > MAX_CALL_BYTES {
            return Err(ContractError::InputTooLarge);
        }
        let call: Call = serde_json::from_slice(bytes).map_err(|_| ContractError::InvalidCall)?;
        let validated = self
            .routes
            .get(&call.route)
            .ok_or(ContractError::UnknownRoute)?;
        if bytes.len() > validated.route.max_request_bytes {
            return Err(ContractError::InputTooLarge);
        }
        let arguments = Value::Object(call.arguments.clone());
        if !integer_numbers_only(&arguments) || !validated.validator.is_valid(&arguments) {
            return Err(ContractError::ArgumentsRejected);
        }
        let snapshot = serde_json::json!({
            "contract_version": PREPARED_CONTRACT_VERSION,
            "route": &validated.route,
            "arguments": arguments,
        });
        let mut hash = Sha256::new();
        hash.update(b"opaque.mcp.prepared-call.v2\0");
        hash.update(serde_json::to_vec(&key_sorted(snapshot)).expect("JSON value serializes"));
        let digest = format!("{:x}", hash.finalize());
        Ok(PreparedCall {
            route: validated.route.clone(),
            arguments: call.arguments,
            digest,
        })
    }
}

fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn validate_endpoint(endpoint: &Endpoint) -> Result<(), ContractError> {
    let host = endpoint.host.as_str();
    let labels: Vec<_> = host.split('.').collect();
    let host_valid = host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // Reject address literals, numeric shorthand, local/metadata names.
        && labels.last().is_some_and(|label| label.bytes().any(|b| b.is_ascii_lowercase()))
        && !matches!(labels.last().copied(), Some("localhost" | "local" | "internal"));
    let path = endpoint.path.as_str();
    let path_valid = path.starts_with('/')
        && path.len() <= 256
        && !path.contains("//")
        && path.split('/').all(|part| part != "." && part != "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-~".contains(&b));
    if host_valid && path_valid {
        Ok(())
    } else {
        Err(ContractError::InvalidEndpoint)
    }
}

/// Intentionally small finite JSON Schema subset. All objects are closed;
/// strings/arrays need upper bounds. No refs, patterns, combinators, defaults,
/// dynamic anchors or annotations are accepted as implicit authority.
fn validate_schema(schema: &Value, depth: usize, nodes: &mut usize) -> Result<(), ContractError> {
    *nodes += 1;
    if depth > MAX_SCHEMA_DEPTH || *nodes > MAX_SCHEMA_NODES {
        return Err(ContractError::InvalidSchema);
    }
    let object = schema.as_object().ok_or(ContractError::InvalidSchema)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ContractError::InvalidSchema)?;
    let allowed: &[&str] = match kind {
        "object" => &["type", "properties", "required", "additionalProperties"],
        "string" => &["type", "minLength", "maxLength", "enum"],
        "integer" => &["type", "minimum", "maximum", "enum"],
        "boolean" => &["type", "enum"],
        "array" => &["type", "items", "minItems", "maxItems"],
        _ => return Err(ContractError::InvalidSchema),
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ContractError::InvalidSchema);
    }
    match kind {
        "object" => {
            if object.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(ContractError::InvalidSchema);
            }
            let properties = object
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(ContractError::InvalidSchema)?;
            if properties.len() > 64 || properties.keys().any(|key| !identifier(key)) {
                return Err(ContractError::InvalidSchema);
            }
            if let Some(required) = object.get("required") {
                let required = required.as_array().ok_or(ContractError::InvalidSchema)?;
                let mut names = BTreeSet::new();
                for name in required {
                    let name = name.as_str().ok_or(ContractError::InvalidSchema)?;
                    if !properties.contains_key(name) || !names.insert(name) {
                        return Err(ContractError::InvalidSchema);
                    }
                }
            }
            for property in properties.values() {
                validate_schema(property, depth + 1, nodes)?;
            }
        }
        "string" => validate_range(object, "minLength", "maxLength", 4096)?,
        "array" => {
            validate_range(object, "minItems", "maxItems", 256)?;
            validate_schema(
                object.get("items").ok_or(ContractError::InvalidSchema)?,
                depth + 1,
                nodes,
            )?;
        }
        "integer" => {
            let minimum = object
                .get("minimum")
                .and_then(Value::as_i64)
                .ok_or(ContractError::InvalidSchema)?;
            let maximum = object
                .get("maximum")
                .and_then(Value::as_i64)
                .ok_or(ContractError::InvalidSchema)?;
            if minimum > maximum {
                return Err(ContractError::InvalidSchema);
            }
        }
        _ => {}
    }
    if let Some(values) = object.get("enum") {
        let values = values.as_array().ok_or(ContractError::InvalidSchema)?;
        if values.is_empty()
            || values.len() > 64
            || values.iter().any(|value| match kind {
                "string" => !value.is_string(),
                "integer" => value.as_i64().is_none(),
                "boolean" => !value.is_boolean(),
                _ => true,
            })
        {
            return Err(ContractError::InvalidSchema);
        }
    }
    Ok(())
}

fn validate_range(
    object: &Map<String, Value>,
    lower: &str,
    upper: &str,
    cap: u64,
) -> Result<(), ContractError> {
    let maximum = object
        .get(upper)
        .and_then(Value::as_u64)
        .ok_or(ContractError::InvalidSchema)?;
    let minimum = match object.get(lower) {
        Some(value) => value.as_u64().ok_or(ContractError::InvalidSchema)?,
        None => 0,
    };
    if minimum <= maximum && maximum <= cap {
        Ok(())
    } else {
        Err(ContractError::InvalidSchema)
    }
}

fn key_sorted(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<_, _> = object
                .into_iter()
                .map(|(key, value)| (key, key_sorted(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(key_sorted).collect()),
        other => other,
    }
}

// JSON Schema regards 2.0 as an integer. Contract v1 instead accepts only the
// signed integer JSON representation, avoiding floating-point hash ambiguity.
fn integer_numbers_only(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_i64().is_some(),
        Value::Object(object) => object.values().all(integer_numbers_only),
        Value::Array(values) => values.iter().all(integer_numbers_only),
        _ => true,
    }
}
