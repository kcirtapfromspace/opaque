use super::{SlackConfig, store::Notice};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub struct SlackTransport {
    config: SlackConfig,
    endpoint: reqwest::Url,
    client: reqwest::Client,
}

impl SlackTransport {
    pub fn new(config: SlackConfig) -> Result<Self, String> {
        if !(config.channel_id.starts_with('C')
            || config.channel_id.starts_with('G')
            || config.channel_id.starts_with('D'))
            || !(2..=64).contains(&config.channel_id.len())
            || !config
                .channel_id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || !config.token_file.is_absolute()
        {
            return Err("invalid Slack notification configuration".into());
        }
        let endpoint = match &config.fixture_endpoint {
            None => reqwest::Url::parse("https://slack.com/api/chat.postMessage")
                .expect("fixed Slack URL"),
            Some(value) => {
                let url =
                    reqwest::Url::parse(value).map_err(|_| "invalid Slack fixture endpoint")?;
                let ip = url.host_str().and_then(|host| {
                    host.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .ok()
                });
                if url.scheme() != "http"
                    || !ip.is_some_and(|ip| ip.is_loopback())
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.path() != "/api/chat.postMessage"
                {
                    return Err("Slack fixture endpoint must be literal loopback HTTP".into());
                }
                url
            }
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| "Slack notification client unavailable")?;
        Ok(Self {
            config,
            endpoint,
            client,
        })
    }

    fn token(&self) -> Result<String, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.config.token_file)
            .map_err(|_| "Slack token unavailable")?;
        let meta = file.metadata().map_err(|_| "Slack token unavailable")?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.len() > 4096
        {
            return Err("Slack token requires an owner-only bounded regular file".into());
        }
        let mut token = String::new();
        file.take(4097)
            .read_to_string(&mut token)
            .map_err(|_| "Slack token unavailable")?;
        let token = token.trim_end_matches('\n').to_owned();
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|b| (b'!'..=b'~').contains(&b))
        {
            return Err("invalid Slack token file".into());
        }
        // A loopback fixture must not accidentally transmit a production token.
        if self.config.fixture_endpoint.is_some() && token != "opaque-slack-fixture-token" {
            return Err("Slack fixture endpoint requires its fixed synthetic token".into());
        }
        Ok(token)
    }

    pub async fn send(&self, notice: &Notice) -> Result<(), String> {
        if super::now() >= notice.expires_at {
            return Err("notification expired".into());
        }
        let link = opaque_core::workstation::notice_link(&notice.broker_id, &notice.approval_id)
            .map_err(|_| "invalid approval notice")?;
        let body = serde_json::json!({
            "channel":self.config.channel_id,
            "text":format!("Opaque approval is waiting on your trusted workstation.\nReview reference: {link}\nUse the enrolled Opaque approver. This message cannot authorize execution."),
            "mrkdwn":false,"parse":"none","unfurl_links":false,"unfurl_media":false,
        });
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.token()?)
            .json(&body)
            .send()
            .await
            .map_err(|_| "Slack delivery outcome unknown")?;
        if !response.status().is_success()
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
                })
            || response.content_length().is_some_and(|n| n > 16384)
        {
            return Err("Slack delivery was not acknowledged".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Slack delivery outcome unknown")?
        {
            if bytes.len() + chunk.len() > 16384 {
                return Err("Slack response exceeds limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid Slack acknowledgment")?;
        if value.get("ok").and_then(|v| v.as_bool()) != Some(true)
            || value.get("channel").and_then(|v| v.as_str()) != Some(&self.config.channel_id)
            || !value.get("ts").and_then(|v| v.as_str()).is_some_and(|v| {
                !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            })
        {
            return Err("Slack delivery was not acknowledged".into());
        }
        Ok(())
    }
}
