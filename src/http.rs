//! Internal HTTP layer. Not part of the public API.
//!
//! Exposes `send_magic_link`, `validate_session`, `logout` as free async
//! functions. Retry (2x on 5xx, exponential backoff) and timeout (10s) are
//! hard-coded. `STACKURE_BASE_URL` overrides the base URL.

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, COOKIE};

use crate::errors::StackureError;
use crate::types::{MagicLinkResponse, SendMagicLinkRequest, SessionValidationResponse};
use crate::validation::{validate_email, validate_uuid};

const DEFAULT_BASE_URL: &str = "https://stackure.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RETRIES: u32 = 2;

/// Resolve the base URL from `STACKURE_BASE_URL` or fall back to production.
fn base_url() -> String {
    env::var("STACKURE_BASE_URL").map_or_else(
        |_| DEFAULT_BASE_URL.to_string(),
        |v| v.trim_end_matches('/').to_string(),
    )
}

/// Shared reqwest client. Initialized lazily on first use.
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .cookie_store(true)
            .build()
            .expect("failed to build HTTP client")
    })
}

/// Perform an HTTP request with retry on 5xx (exponential backoff) and no
/// retry on timeouts.
async fn request(
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
    cookies: Option<&str>,
    query: Option<&[(&str, &str)]>,
) -> Result<reqwest::Response, StackureError> {
    let url = format!("{}{}", base_url(), path);
    let mut last_error: Option<StackureError> = None;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = Duration::from_millis(500 * (1 << (attempt - 1)));
            tokio::time::sleep(delay).await;
        }

        let mut req = http().request(method.clone(), &url);

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
                        REQUEST_TIMEOUT.as_secs()
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

/// Map non-2xx responses to typed [`StackureError`].
fn handle_status(status: u16, body: &str) -> Result<(), StackureError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    if status == 401 {
        let msg = if body.is_empty() {
            "Authentication failed"
        } else {
            body
        };
        return Err(StackureError::Auth(msg.to_string()));
    }
    if status == 403 {
        let msg = if body.is_empty() {
            "Access forbidden"
        } else {
            body
        };
        return Err(StackureError::Forbidden(msg.to_string()));
    }
    Err(StackureError::Network(format!(
        "API error ({status}): {body}"
    )))
}

/// Send a passwordless sign-in email to a user.
pub(crate) async fn send_magic_link(
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

    let response = request(
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
    handle_status(status, &text)?;

    serde_json::from_str::<MagicLinkResponse>(&text)
        .map_err(|_| StackureError::Network("Unexpected API response format".into()))
}

/// Validate a session cookie. Internal — callers use [`crate::verify`].
pub(crate) async fn validate_session(
    app_id: &str,
    cookies: Option<&str>,
) -> Result<SessionValidationResponse, StackureError> {
    validate_uuid(app_id, "App ID")?;

    let response = request(
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
    handle_status(status, &text)?;

    serde_json::from_str::<SessionValidationResponse>(&text)
        .map_err(|_| StackureError::Network("Unexpected API response format".into()))
}

/// Revoke the session represented by the given cookies.
pub(crate) async fn logout(cookies: Option<&str>) -> Result<(), StackureError> {
    let response = request(
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
    handle_status(status, &text)?;
    Ok(())
}
