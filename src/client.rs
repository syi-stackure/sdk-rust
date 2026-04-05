//! HTTP client for the Stackure authentication API.

use std::time::Duration;

use reqwest::header::{COOKIE, HeaderMap, HeaderValue};

use crate::errors::StackureError;
use crate::types::{MagicLinkResponse, SendMagicLinkRequest, SessionValidationResponse};
use crate::validation::{validate_email, validate_uuid};

const DEFAULT_BASE_URL: &str = "https://stackure.com";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RETRIES: u32 = 2;

/// Configuration for the Stackure HTTP client.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the Stackure API. Defaults to `https://stackure.com`.
    pub base_url: String,
    /// Request timeout. Defaults to 10 seconds.
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Client for the Stackure authentication API.
///
/// Wraps the Stackure REST endpoints for magic-link authentication, session
/// validation, and sign-out. All methods are asynchronous.
///
/// # Example
///
/// ```no_run
/// use stackure::{Client, Config};
///
/// # async fn example() -> Result<(), stackure::StackureError> {
/// let client = Client::new(Config::default());
/// let response = client.send_magic_link("user@example.com", None).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    config: Config,
    http: reqwest::Client,
}

impl Client {
    /// Create a new client with the given configuration.
    pub fn new(config: Config) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .cookie_store(true)
            .build()
            .expect("failed to build HTTP client");
        Self { config, http }
    }

    /// Create a new client with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(Config::default())
    }

    /// Execute an HTTP request with retry logic.
    ///
    /// Retries up to 2 times on 5xx errors with exponential backoff (500ms, 1s).
    /// Timeouts are never retried.
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        cookies: Option<&str>,
        query: Option<&[(&str, &str)]>,
    ) -> Result<reqwest::Response, StackureError> {
        let url = format!("{}{}", self.config.base_url, path);
        let mut last_error: Option<StackureError> = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                // Exponential backoff: 500ms, 1000ms
                let delay = Duration::from_millis(500 * (1 << (attempt - 1)));
                tokio::time::sleep(delay).await;
            }

            let mut req = self.http.request(method.clone(), &url);

            if let Some(q) = query {
                req = req.query(q);
            }
            if let Some(ref b) = body {
                req = req.json(b);
            }
            if let Some(cookie_str) = cookies {
                let mut headers = HeaderMap::new();
                if let Ok(val) = HeaderValue::from_str(cookie_str) {
                    headers.insert(COOKIE, val);
                }
                req = req.headers(headers);
            }

            match req.send().await {
                Ok(response) => {
                    if response.status().is_server_error() && attempt < MAX_RETRIES {
                        last_error = Some(StackureError::Network(format!(
                            "Server error ({})",
                            response.status().as_u16()
                        )));
                        continue;
                    }
                    return Ok(response);
                }
                Err(e) => {
                    if e.is_timeout() {
                        return Err(StackureError::Timeout(format!(
                            "Request timed out after {}s",
                            self.config.timeout.as_secs()
                        )));
                    }
                    last_error = Some(StackureError::Network(format!(
                        "Network request failed: {e}"
                    )));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| StackureError::Network("Request failed after retries".into())))
    }

    /// Parse a successful JSON response body, mapping HTTP errors to SDK errors.
    fn handle_response_status(status: u16, body: &str) -> Result<(), StackureError> {
        if (200..300).contains(&status) {
            return Ok(());
        }
        if status == 401 {
            let msg = if body.is_empty() {
                "Authentication failed"
            } else {
                body
            };
            return Err(StackureError::Authentication(msg.to_string()));
        }
        Err(StackureError::Network(format!(
            "API error ({status}): {body}"
        )))
    }

    /// Send a magic-link authentication email to a user.
    ///
    /// # Errors
    ///
    /// Returns [`StackureError::Validation`] if `email` or `app_id` fails validation.
    /// Returns [`StackureError::Network`] if the request fails.
    /// Returns [`StackureError::Timeout`] if the request times out.
    pub async fn send_magic_link(
        &self,
        email: &str,
        app_id: Option<&str>,
    ) -> Result<MagicLinkResponse, StackureError> {
        validate_email(email)?;
        if let Some(id) = app_id {
            validate_uuid(id, "App ID")?;
        }

        let request_body = SendMagicLinkRequest {
            user_email: email.to_string(),
            app_id: app_id.map(String::from),
        };
        let body = serde_json::to_value(&request_body)
            .map_err(|e| StackureError::Network(format!("Failed to serialize request: {e}")))?;

        let response = self
            .request(
                reqwest::Method::POST,
                "/api/public/auth/magic-link/send",
                Some(body),
                None,
                None,
            )
            .await?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| StackureError::Network(format!("Failed to read response: {e}")))?;
        Self::handle_response_status(status, &text)?;

        serde_json::from_str::<MagicLinkResponse>(&text)
            .map_err(|_| StackureError::Network("Unexpected API response format".into()))
    }

    /// Validate the current session for an application.
    ///
    /// # Errors
    ///
    /// Returns [`StackureError::Validation`] if `app_id` fails validation.
    /// Returns [`StackureError::Network`] if the request fails.
    /// Returns [`StackureError::Timeout`] if the request times out.
    pub async fn validate_session(
        &self,
        app_id: &str,
        cookies: Option<&str>,
    ) -> Result<SessionValidationResponse, StackureError> {
        validate_uuid(app_id, "App ID")?;

        let response = self
            .request(
                reqwest::Method::GET,
                "/api/public/auth/session/validate",
                None,
                cookies,
                Some(&[("app_id", app_id)]),
            )
            .await?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| StackureError::Network(format!("Failed to read response: {e}")))?;
        Self::handle_response_status(status, &text)?;

        serde_json::from_str::<SessionValidationResponse>(&text)
            .map_err(|_| StackureError::Network("Unexpected API response format".into()))
    }

    /// Sign out the current user from all Stackure applications.
    ///
    /// # Errors
    ///
    /// Returns [`StackureError::Network`] if the request fails.
    /// Returns [`StackureError::Timeout`] if the request times out.
    pub async fn logout(&self, cookies: Option<&str>) -> Result<(), StackureError> {
        let response = self
            .request(
                reqwest::Method::POST,
                "/api/public/auth/sign-out",
                None,
                cookies,
                None,
            )
            .await?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| StackureError::Network(format!("Failed to read response: {e}")))?;
        Self::handle_response_status(status, &text)?;
        Ok(())
    }

    /// Initiate sign-in for a user.
    ///
    /// When `email` is provided, sends a magic-link directly. When omitted,
    /// returns `None`; callers in browser environments should redirect to
    /// the `sign_in_url` returned by [`validate_session`](Self::validate_session).
    ///
    /// # Errors
    ///
    /// Returns [`StackureError::Validation`] if `app_id` or `email` fails validation.
    pub async fn sign_in(
        &self,
        app_id: &str,
        email: Option<&str>,
    ) -> Result<Option<MagicLinkResponse>, StackureError> {
        validate_uuid(app_id, "App ID")?;
        if let Some(email) = email {
            let response = self.send_magic_link(email, Some(app_id)).await?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::with_defaults()
    }
}
