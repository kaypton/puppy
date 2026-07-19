//! HTTP client for the puppy dashboard API (docs/HTTP-API.md).

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::api::types::{
    BackendsResponse, ConfigResponse, ConnectionsResponse, FrontendsResponse, JobAccepted, Stats,
    SystemInfo,
};
use crate::config::ConnectionConfig;

/// URL prefix shared by every endpoint.
pub const API_PREFIX: &str = "/api/v1";

/// Errors surfaced to the UI.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The server answered with a non-2xx status.
    #[error("{msg}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Message parsed from the `{"error": "..."}` body, or a fallback.
        msg: String,
    },
    /// Transport-level failure (DNS, connect, TLS, timeout...).
    #[error("{0}")]
    Transport(String),
}

impl ApiError {
    /// HTTP status when this is an HTTP error, else None.
    pub fn status(&self) -> Option<u16> {
        match self {
            ApiError::Http { status, .. } => Some(*status),
            ApiError::Transport(_) => None,
        }
    }
}

/// Cloneable REST client wrapping reqwest.
#[derive(Debug, Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    /// Base URL with trailing slashes trimmed, e.g. `https://127.0.0.1:8443`.
    base: String,
}

impl ApiClient {
    /// Builds a client from the connection configuration.
    pub fn new(cfg: &ConnectionConfig) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        if let Some(token) = cfg.token.as_deref().filter(|t| !t.is_empty()) {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
            headers.insert(AUTHORIZATION, value);
        }

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .danger_accept_invalid_certs(cfg.ignore_tls)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self {
            http,
            base: cfg.server.trim_end_matches('/').to_string(),
        })
    }

    /// Full URL for an API path like `/stats`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}{}", self.base, API_PREFIX, path)
    }

    /// Raw reqwest client (used by the SSE subscriber which manages its own request).
    pub fn raw(&self) -> &reqwest::Client {
        &self.http
    }

    /// GET `path` and decode the JSON body.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .http
            .get(self.url(path))
            .send()
            .await
            .map_err(transport_err)?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>().await.map_err(transport_err)
        } else {
            Err(http_err(status.as_u16(), resp).await)
        }
    }

    /// POST `path` with an empty body and decode the JSON response.
    pub async fn post<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .http
            .post(self.url(path))
            .send()
            .await
            .map_err(transport_err)?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>().await.map_err(transport_err)
        } else {
            Err(http_err(status.as_u16(), resp).await)
        }
    }

    /// GET /system.
    pub async fn system(&self) -> Result<SystemInfo, ApiError> {
        self.get("/system").await
    }

    /// GET /stats.
    pub async fn stats(&self) -> Result<Stats, ApiError> {
        self.get("/stats").await
    }

    /// GET /connections, optionally filtered by frontend name.
    pub async fn connections(
        &self,
        frontend: Option<&str>,
    ) -> Result<ConnectionsResponse, ApiError> {
        match frontend {
            Some(name) => self.get(&format!("/connections?frontend={name}")).await,
            None => self.get("/connections").await,
        }
    }

    /// GET /frontends.
    pub async fn frontends(&self) -> Result<FrontendsResponse, ApiError> {
        self.get("/frontends").await
    }

    /// GET /backends.
    pub async fn backends(&self) -> Result<BackendsResponse, ApiError> {
        self.get("/backends").await
    }

    /// GET /config (sanitized runtime config as raw JSON).
    pub async fn config(&self) -> Result<ConfigResponse, ApiError> {
        self.get("/config").await
    }

    /// POST /config/reload — fire-and-forget control request.
    pub async fn reload(&self) -> Result<JobAccepted, ApiError> {
        self.post("/config/reload").await
    }
}

fn transport_err(err: reqwest::Error) -> ApiError {
    ApiError::Transport(err.to_string())
}

/// Builds an ApiError::Http from a non-2xx response, preferring the
/// `{"error": "..."}` body, then raw text, then the bare status code.
async fn http_err(status: u16, resp: reqwest::Response) -> ApiError {
    let body = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<crate::api::types::ApiErrorBody>(&body)
        .map(|b| b.error)
        .ok()
        .filter(|m| !m.is_empty())
        .or(if body.is_empty() { None } else { Some(body) })
        .unwrap_or_else(|| format!("HTTP {status}"));
    ApiError::Http { status, msg }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(server: &str) -> ConnectionConfig {
        ConnectionConfig {
            server: server.to_string(),
            token: None,
            ignore_tls: false,
        }
    }

    #[test]
    fn url_trims_trailing_slashes() {
        let client = ApiClient::new(&cfg("https://127.0.0.1:8443///")).unwrap();
        assert_eq!(client.url("/stats"), "https://127.0.0.1:8443/api/v1/stats");
    }

    #[test]
    fn url_joins_prefix() {
        let client = ApiClient::new(&cfg("http://[::1]:9000")).unwrap();
        assert_eq!(client.url("/system"), "http://[::1]:9000/api/v1/system");
    }

    #[test]
    fn client_with_token_builds() {
        let mut c = cfg("https://127.0.0.1:8443");
        c.token = Some("secret".into());
        assert!(ApiClient::new(&c).is_ok());
    }

    #[test]
    fn client_with_ignore_tls_builds() {
        let mut c = cfg("https://127.0.0.1:8443");
        c.ignore_tls = true;
        assert!(ApiClient::new(&c).is_ok());
    }
}
