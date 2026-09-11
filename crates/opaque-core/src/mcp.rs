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
pub const PREPARED_CONTRACT_VERSION: u32 = 3;
pub const MAX_UPSTREAM_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_CATALOG_BYTES: usize = 256 * 1024;
pub const MAX_PROJECTED_BYTES: usize = 1024;
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
    UnsupportedUpstreamSchema,
    InvalidProjection,
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
            Self::UnsupportedUpstreamSchema => "unsupported pinned upstream schema",
            Self::InvalidProjection => "invalid bounded result projection",
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
    /// Only signed fields from structuredContent, after current authority checks.
    TypedFields,
}

impl OutputPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Withhold => "withhold",
            Self::TypedFields => "typed_fields",
        }
    }
}

/// The only permitted output values are bounded numeric IDs and signed status
/// enums. No text, URLs, JSON pointers, nested values or caller-selected fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResultFieldType {
    IntegerId { maximum: u64 },
    Status { values: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultField {
    pub source: String,
    pub name: String,
    pub value_type: ResultFieldType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultProjection {
    pub fields: Vec<ResultField>,
}

impl ResultProjection {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.fields.is_empty() || self.fields.len() > 8 {
            return Err(ContractError::InvalidProjection);
        }
        let mut sources = BTreeSet::new();
        let mut names = BTreeSet::new();
        for field in &self.fields {
            if !identifier(&field.source)
                || !identifier(&field.name)
                || !sources.insert(&field.source)
                || !names.insert(&field.name)
            {
                return Err(ContractError::InvalidProjection);
            }
            match &field.value_type {
                ResultFieldType::IntegerId { maximum }
                    if !(1..=9_007_199_254_740_991).contains(maximum) =>
                {
                    return Err(ContractError::InvalidProjection);
                }
                ResultFieldType::Status { values } => {
                    let unique: BTreeSet<_> = values.iter().collect();
                    if values.is_empty()
                        || values.len() > 16
                        || unique.len() != values.len()
                        || values.iter().any(|v| v.len() > 32 || !identifier(v))
                    {
                        return Err(ContractError::InvalidProjection);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Unselected fields are ignored; a missing, malformed or out-of-contract
    /// selected field rejects the entire projection. Tool errors never call this.
    pub fn project(&self, structured: &Value) -> Result<BTreeMap<String, Value>, ContractError> {
        self.validate()?;
        let object = structured
            .as_object()
            .ok_or(ContractError::InvalidProjection)?;
        let mut output = BTreeMap::new();
        for field in &self.fields {
            let value = object
                .get(&field.source)
                .ok_or(ContractError::InvalidProjection)?;
            let valid = match &field.value_type {
                ResultFieldType::IntegerId { maximum } => {
                    value.as_u64().is_some_and(|v| (1..=*maximum).contains(&v))
                }
                ResultFieldType::Status { values } => value
                    .as_str()
                    .is_some_and(|v| values.iter().any(|allowed| allowed == v)),
            };
            if !valid {
                return Err(ContractError::InvalidProjection);
            }
            output.insert(field.name.clone(), value.clone());
        }
        if serde_json::to_vec(&output)
            .map_err(|_| ContractError::InvalidProjection)?
            .len()
            > MAX_PROJECTED_BYTES
        {
            return Err(ContractError::InvalidProjection);
        }
        Ok(output)
    }
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
    /// Registry v2: exact advertised schema pin, separately validated from the
    /// finite admitted input_schema. Absent in v1, where input_schema is the pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_input_schema: Option<Value>,
    pub output_policy: OutputPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_projection: Option<ResultProjection>,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub timeout_ms: u64,
}

impl Route {
    pub fn upstream_schema(&self) -> &Value {
        self.upstream_input_schema
            .as_ref()
            .unwrap_or(&self.input_schema)
    }

    pub fn prepared_contract_version(&self) -> u32 {
        if self.upstream_input_schema.is_some() {
            PREPARED_CONTRACT_VERSION
        } else {
            2
        }
    }
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
    upstream_validator: Option<jsonschema::Validator>,
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
        if !matches!(document.version, 1 | 2)
            || document.routes.is_empty()
            || document.routes.len() > 128
        {
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
            if document.version == 2
                && serde_json::to_vec(&route.input_schema)
                    .map_err(|_| ContractError::InvalidSchema)?
                    .len()
                    > MAX_UPSTREAM_SCHEMA_BYTES
            {
                return Err(ContractError::InvalidSchema);
            }
            match (
                document.version,
                &route.upstream_input_schema,
                route.output_policy,
                &route.output_projection,
            ) {
                (1, None, OutputPolicy::Withhold, None) => {}
                (2, Some(_), OutputPolicy::Withhold, None) => {}
                (2, Some(_), OutputPolicy::TypedFields, Some(projection)) => {
                    projection.validate()?
                }
                _ => return Err(ContractError::InvalidRegistry),
            }
            let mut nodes = 0;
            validate_schema(&route.input_schema, 0, &mut nodes)?;
            if route.input_schema["type"] != "object" {
                return Err(ContractError::InvalidSchema);
            }
            // The admitted schema subset contains no references or regexes.
            // Compilation cannot resolve URLs, files or external schemas.
            let validator = jsonschema::validator_for(&route.input_schema)
                .map_err(|_| ContractError::InvalidSchema)?;
            let upstream_validator = route
                .upstream_input_schema
                .as_ref()
                .map(|schema| {
                    validate_upstream_schema(schema)?;
                    jsonschema::validator_for(schema)
                        .map_err(|_| ContractError::UnsupportedUpstreamSchema)
                })
                .transpose()?;
            routes.insert(
                route.alias.clone(),
                ValidatedRoute {
                    route,
                    validator,
                    upstream_validator,
                },
            );
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

    /// Offline comparison against a captured tools/list result. This proves pin
    /// equality only, not authorization, endpoint provenance or all possible
    /// argument compatibility. Every runtime call still validates both schemas.
    pub fn qualify_catalog(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<CatalogQualification>, ContractError> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(ContractError::InputTooLarge);
        }
        let catalog: Value =
            serde_json::from_slice(bytes).map_err(|_| ContractError::InvalidRegistry)?;
        let result = catalog.get("result").unwrap_or(&catalog);
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or(ContractError::InvalidRegistry)?;
        if result.get("nextCursor").is_some() || tools.len() > 128 {
            return Err(ContractError::InvalidRegistry);
        }
        Ok(self
            .routes
            .values()
            .map(|value| {
                let route = &value.route;
                let matches: Vec<_> = tools
                    .iter()
                    .filter(|t| t.get("name").and_then(Value::as_str) == Some(&route.tool))
                    .collect();
                let diagnostic = match matches.as_slice() {
                    [] => "tool_missing",
                    [tool] if tool.get("inputSchema") == Some(route.upstream_schema()) => {
                        "pinned_schema_matches"
                    }
                    [_] => "upstream_schema_drift",
                    _ => "duplicate_tool",
                };
                CatalogQualification {
                    route: route.alias.clone(),
                    compatible: diagnostic == "pinned_schema_matches",
                    diagnostic,
                }
            })
            .collect())
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
        if !integer_numbers_only(&arguments)
            || !validated.validator.is_valid(&arguments)
            || validated
                .upstream_validator
                .as_ref()
                .is_some_and(|v| !v.is_valid(&arguments))
        {
            return Err(ContractError::ArgumentsRejected);
        }
        let snapshot = serde_json::json!({
            "contract_version": validated.route.prepared_contract_version(),
            "route": &validated.route,
            "arguments": arguments,
        });
        let mut hash = Sha256::new();
        hash.update(if validated.route.prepared_contract_version() == 2 {
            b"opaque.mcp.prepared-call.v2\0"
        } else {
            b"opaque.mcp.prepared-call.v3\0"
        });
        hash.update(serde_json::to_vec(&key_sorted(snapshot)).expect("JSON value serializes"));
        let digest = format!("{:x}", hash.finalize());
        Ok(PreparedCall {
            route: validated.route.clone(),
            arguments: call.arguments,
            digest,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CatalogQualification {
    pub route: String,
    pub compatible: bool,
    pub diagnostic: &'static str,
}

/// Bounded non-referencing subset of upstream JSON Schema. Unlike the admitted
/// contract, upstream properties may be open/unbounded and carry descriptions.
/// These annotations never become defaults, agent tools, review text or authority.
/// Reject refs, regexes, combinators and unknown keywords before compilation, so
/// the validator cannot retrieve schemas or perform unbounded regex evaluation.
fn validate_upstream_schema(schema: &Value) -> Result<(), ContractError> {
    fn visit(schema: &Value, depth: usize, nodes: &mut usize) -> Result<(), ContractError> {
        let error = ContractError::UnsupportedUpstreamSchema;
        *nodes += 1;
        if depth > MAX_SCHEMA_DEPTH || *nodes > MAX_SCHEMA_NODES {
            return Err(error);
        }
        let obj = schema.as_object().ok_or(error)?;
        let kind = obj.get("type").and_then(Value::as_str).ok_or(error)?;
        let allowed: &[&str] = match kind {
            "object" => &[
                "type",
                "properties",
                "required",
                "additionalProperties",
                "description",
                "title",
            ],
            "string" => &[
                "type",
                "minLength",
                "maxLength",
                "enum",
                "description",
                "title",
            ],
            "number" | "integer" => &["type", "minimum", "maximum", "enum", "description", "title"],
            "boolean" => &["type", "enum", "description", "title"],
            "array" => &[
                "type",
                "items",
                "minItems",
                "maxItems",
                "description",
                "title",
            ],
            _ => return Err(error),
        };
        if obj.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(error);
        }
        for key in ["description", "title"] {
            if obj
                .get(key)
                .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 4096))
            {
                return Err(error);
            }
        }
        if let Some(values) = obj.get("enum") {
            let values = values.as_array().ok_or(error)?;
            if values.is_empty()
                || values.len() > 128
                || values
                    .iter()
                    .any(|v| !(v.is_string() || v.is_number() || v.is_boolean()))
            {
                return Err(error);
            }
        }
        match kind {
            "object" => {
                let properties = obj
                    .get("properties")
                    .and_then(Value::as_object)
                    .ok_or(error)?;
                if properties.len() > 64 || properties.keys().any(|key| !identifier(key)) {
                    return Err(error);
                }
                if obj
                    .get("additionalProperties")
                    .is_some_and(|v| !v.is_boolean())
                {
                    return Err(error);
                }
                if let Some(required) = obj.get("required") {
                    let required = required.as_array().ok_or(error)?;
                    let unique: BTreeSet<_> = required.iter().filter_map(Value::as_str).collect();
                    if required.len() > 64
                        || unique.len() != required.len()
                        || unique.iter().any(|key| !properties.contains_key(*key))
                    {
                        return Err(error);
                    }
                }
                for child in properties.values() {
                    visit(child, depth + 1, nodes)?;
                }
            }
            "array" => visit(obj.get("items").ok_or(error)?, depth + 1, nodes)?,
            _ => {}
        }
        Ok(())
    }
    if serde_json::to_vec(schema)
        .map_err(|_| ContractError::UnsupportedUpstreamSchema)?
        .len()
        > MAX_UPSTREAM_SCHEMA_BYTES
        || schema.get("type").and_then(Value::as_str) != Some("object")
    {
        return Err(ContractError::UnsupportedUpstreamSchema);
    }
    visit(schema, 0, &mut 0)
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
