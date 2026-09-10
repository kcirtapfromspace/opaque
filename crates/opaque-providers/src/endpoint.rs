//! Credential-free endpoint configuration shared by prepared provider actions.

pub(crate) fn parse_endpoint(value: &str) -> Result<reqwest::Url, &'static str> {
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err("invalid API endpoint URL");
    }
    let parsed = reqwest::Url::parse(value).map_err(|_| "invalid API endpoint URL")?;
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or(""));
    if parsed.host_str().is_none()
        || parsed.cannot_be_a_base()
        || authority.is_none_or(str::is_empty)
    {
        return Err("invalid API endpoint URL");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority.is_some_and(|value| value.contains('@'))
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("API endpoint must not contain userinfo, query or fragment");
    }
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("unsupported URL scheme");
    }
    Ok(parsed)
}

pub(crate) fn validate_http_endpoint(value: &str) -> Result<(), &'static str> {
    let parsed = parse_endpoint(value)?;
    if parsed.scheme() == "http" && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1")) {
        return Err("insecure HTTP URL rejected; only localhost or 127.0.0.1 is permitted");
    }
    Ok(())
}
