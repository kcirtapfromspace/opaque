//! Fixed llama.cpp protocol. Requests are assembled here, never forwarded.

use opaque_core::inference::{INFERENCE_INPUT_TOKENS, INFERENCE_OUTPUT_TOKENS, sha256};
use serde::Deserialize;
use serde_json::json;

use super::{TrustedInferenceProfile, unavailable};

pub(super) struct InferenceClient {
    http: reqwest::Client,
    base: reqwest::Url,
}

pub(super) enum CompletionResult {
    Observed { output: String, tokens: u32 },
    Rejected,
    Unknown,
    ContractViolation,
}

impl InferenceClient {
    pub(super) fn new(profile: &TrustedInferenceProfile) -> Result<Self, String> {
        profile.validate()?;
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|_| unavailable())?,
            base: reqwest::Url::parse(&profile.api_url).map_err(|_| unavailable())?,
        })
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut url = self.base.clone();
        url.set_path(path);
        let request = self
            .http
            .request(method, url)
            .header("accept", "application/json");
        if let Some(token) = token {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        limit: usize,
    ) -> Result<T, String> {
        let response = request
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        read_json(response, limit).await.map_err(|_| unavailable())
    }

    pub(super) async fn verify_identity(
        &self,
        profile: &TrustedInferenceProfile,
        token: Option<&str>,
    ) -> Result<(), String> {
        let health: Health = self
            .json(self.request(reqwest::Method::GET, "/health", token), 4096)
            .await?;
        if health.status != "ok" {
            return Err(unavailable());
        }
        let props: Properties = self
            .json(
                self.request(reqwest::Method::GET, "/props", token),
                256 * 1024,
            )
            .await?;
        if props.model_path != profile.model_path
            || props.build_info != profile.server_build
            || sha256(props.chat_template.as_bytes()) != profile.chat_template_sha256
            || props.total_slots != 1
            || props.default_generation_settings.n_ctx
                < INFERENCE_INPUT_TOKENS + INFERENCE_OUTPUT_TOKENS
        {
            return Err(unavailable());
        }
        let models: Models = self
            .json(
                self.request(reqwest::Method::GET, "/v1/models", token),
                32 * 1024,
            )
            .await?;
        if models.data.len() != 1 || models.data[0].id != profile.model_id {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Only a broker-resolved, policy-authorized prompt may reach these two
    /// preprocessing endpoints. Neither endpoint performs token generation.
    pub(super) async fn tokenize_prompt(
        &self,
        prompt: &str,
        token: Option<&str>,
    ) -> Result<Vec<i32>, String> {
        if prompt.is_empty() || prompt.len() > 8192 {
            return Err(unavailable());
        }
        let formatted: FormattedPrompt = self
            .json(
                self.request(reqwest::Method::POST, "/apply-template", token)
                    .json(&json!({"messages":[{"role":"user","content":prompt}]})),
                32 * 1024,
            )
            .await?;
        if formatted.prompt.is_empty() || formatted.prompt.len() > 8192 {
            return Err(unavailable());
        }
        let tokenized: TokenizedPrompt = self.json(
            self.request(reqwest::Method::POST, "/tokenize", token)
                .json(&json!({"content":formatted.prompt,"add_special":false,"parse_special":true,"with_pieces":false})), 32 * 1024,
        ).await?;
        if tokenized.tokens.is_empty()
            || tokenized.tokens.len() > INFERENCE_INPUT_TOKENS as usize
            || tokenized.tokens.iter().any(|token| *token < 0)
        {
            return Err(unavailable());
        }
        Ok(tokenized.tokens)
    }

    pub(super) async fn complete(
        &self,
        profile: &TrustedInferenceProfile,
        tokens: &[i32],
        token: Option<&str>,
    ) -> CompletionResult {
        let response = match self
            .request(reqwest::Method::POST, "/completion", token)
            .json(&json!({
                "model":profile.model_id, "prompt":tokens,
                "n_predict":INFERENCE_OUTPUT_TOKENS, "n_cmpl":1,
                "temperature":0.0, "seed":0, "samplers":["temperature"],
                "cache_prompt":false, "stream":false, "return_tokens":true,
                "ignore_eos":false, "n_probs":0, "n_cache_reuse":0,
                "stop":[], "lora":[]
            }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return CompletionResult::Unknown,
        };
        let status = response.status();
        if status.is_client_error() && status.as_u16() != 408 {
            return CompletionResult::Rejected;
        }
        if status != reqwest::StatusCode::OK {
            return CompletionResult::Unknown;
        }
        let completion: Completion = match read_json(response, 32 * 1024).await {
            Ok(completion) => completion,
            Err(ReadError::Transport) => return CompletionResult::Unknown,
            Err(ReadError::Invalid) => return CompletionResult::ContractViolation,
        };
        if completion.model != profile.model_id
            || !completion.stop
            || completion.truncated
            || completion.tokens_evaluated != tokens.len() as u32
            || completion.tokens_predicted > INFERENCE_OUTPUT_TOKENS
            || completion.tokens.len() != completion.tokens_predicted as usize
            || completion.tokens.iter().any(|token| *token < 0)
            || !matches!(completion.stop_type.as_str(), "eos" | "limit" | "word")
            || completion.content.len() > 8192
            || completion.generation_settings.n_predict != INFERENCE_OUTPUT_TOKENS
        {
            return CompletionResult::ContractViolation;
        }
        CompletionResult::Observed {
            output: completion.content,
            tokens: completion.tokens_predicted,
        }
    }
}

enum ReadError {
    Transport,
    Invalid,
}

async fn read_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T, ReadError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ReadError::Transport)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(ReadError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| ReadError::Invalid)
}

#[derive(Deserialize)]
struct Health {
    status: String,
}
#[derive(Deserialize)]
struct Properties {
    model_path: String,
    build_info: String,
    chat_template: String,
    total_slots: u32,
    default_generation_settings: DefaultSettings,
}
#[derive(Deserialize)]
struct DefaultSettings {
    n_ctx: u32,
}
#[derive(Deserialize)]
struct Models {
    data: Vec<Model>,
}
#[derive(Deserialize)]
struct Model {
    id: String,
}
#[derive(Deserialize)]
struct FormattedPrompt {
    prompt: String,
}
#[derive(Deserialize)]
struct TokenizedPrompt {
    tokens: Vec<i32>,
}
#[derive(Deserialize)]
struct Completion {
    content: String,
    model: String,
    stop: bool,
    truncated: bool,
    stop_type: String,
    tokens_evaluated: u32,
    tokens_predicted: u32,
    tokens: Vec<i32>,
    generation_settings: GenerationSettings,
}
#[derive(Deserialize)]
struct GenerationSettings {
    n_predict: u32,
}
