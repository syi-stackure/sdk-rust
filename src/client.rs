//! HTTP layer for the Stackure SDK, built directly on hyper.

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::errors::StackureError;
use crate::types::{MagicLinkResponse, Session};
use crate::validation::{is_uuid, validate_email, validate_uuid};

const DEFAULT_BASE_URL: &str = "https://stackure.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RETRIES: u32 = 1;
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// Name of the session cookie the SDK reads and writes.
pub const SESSION_COOKIE: &str = "session";
/// Name of the sign-in handoff parameter Stackure sends back.
pub const TOKEN_PARAM: &str = "session_token";

/// Resolve `STACKURE_BASE_URL` from the environment, else production.
#[must_use]
pub fn base_url() -> String {
    env::var("STACKURE_BASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .map_or_else(
            || DEFAULT_BASE_URL.to_string(),
            |v| v.trim_end_matches('/').to_string(),
        )
}

fn app_secret() -> Result<String, StackureError> {
    env::var("STACKURE_APP_SECRET")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| StackureError::Validation("STACKURE_APP_SECRET is not set".into()))
}

pub(crate) fn origin() -> String {
    base_url()
        .parse::<http::Uri>()
        .ok()
        .and_then(|u| Some(format!("{}://{}", u.scheme_str()?, u.authority()?)))
        .unwrap_or_default()
}

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

fn client() -> Result<&'static HttpsClient, StackureError> {
    static CLIENT: OnceLock<Result<HttpsClient, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("no native root certificates found: {e}"))?
                .https_or_http()
                .enable_http1()
                .build();
            Ok(Client::builder(TokioExecutor::new()).build(https))
        })
        .as_ref()
        .map_err(|e| StackureError::Network(e.clone()))
}

#[derive(Default)]
struct CallOpts<'a> {
    body: Option<Vec<u8>>,
    query: Option<String>,
    token: &'a str,
    ua: &'a str,
    ip: &'a str,
}

async fn send_once(
    client: &HttpsClient,
    method: &Method,
    url: &str,
    o: &CallOpts<'_>,
    secret: &str,
) -> Result<(u16, Bytes), StackureError> {
    let mut builder = Request::builder().method(method).uri(url);
    if o.body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder = builder.header("x-app-secret", secret);

    let cookie = if o.token.is_empty() {
        String::new()
    } else {
        format!("{SESSION_COOKIE}={}", o.token)
    };
    for (name, value) in [
        ("user-agent", o.ua),
        ("x-forwarded-for", o.ip),
        ("cookie", cookie.as_str()),
    ] {
        if let Some(Ok(v)) = (!value.is_empty()).then(|| HeaderValue::from_str(value)) {
            builder = builder.header(name, v);
        }
    }

    let body = Full::new(Bytes::from(o.body.clone().unwrap_or_default()));
    let req = builder
        .body(body)
        .map_err(|e| StackureError::Network(format!("failed to create request: {e}")))?;

    let response = client
        .request(req)
        .await
        .map_err(|e| StackureError::Network(format!("network request failed: {e}")))?;

    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|_| StackureError::Network("failed to read response body".into()))?
        .to_bytes();
    Ok((status, bytes))
}

async fn request(
    method: &Method,
    path: &str,
    o: CallOpts<'_>,
) -> Result<serde_json::Value, StackureError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let secret = app_secret()?;
    let client = client()?;
    let url = match &o.query {
        Some(q) => format!("{}{path}?{q}", base_url()),
        None => format!("{}{path}", base_url()),
    };

    let mut attempt = 0;
    loop {
        let res = tokio::time::timeout_at(deadline, send_once(client, method, &url, &o, &secret))
            .await
            .map_err(|_| {
                StackureError::Timeout(format!(
                    "request timed out after {}s",
                    REQUEST_TIMEOUT.as_secs()
                ))
            })?;
        let retry = attempt < MAX_RETRIES
            && deadline.saturating_duration_since(tokio::time::Instant::now()) > RETRY_DELAY;
        match res {
            Ok((status, bytes)) if status < 500 || !retry => {
                return handle_response(status, &bytes);
            }
            Err(e) if !retry => return Err(e),
            _ => {}
        }
        attempt += 1;
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

fn handle_response(status: u16, bytes: &[u8]) -> Result<serde_json::Value, StackureError> {
    let text = String::from_utf8_lossy(bytes);
    if !(200..300).contains(&status) {
        let body = if text.is_empty() {
            "unknown error"
        } else {
            &text
        };
        return Err(match status {
            401 => StackureError::Auth(body.to_string()),
            403 => StackureError::Forbidden(body.to_string()),
            _ => StackureError::Network(format!("api error ({status}): {body}")),
        });
    }
    serde_json::from_str(&text)
        .map_err(|_| StackureError::Network("invalid JSON response from server".into()))
}

/// The client's address: first `X-Forwarded-For` entry, else the peer address.
///
/// The peer address is read from axum's `ConnectInfo<SocketAddr>` (with the
/// default `axum` feature) or from a bare `SocketAddr` in the request
/// extensions. Behind a proxy, `X-Forwarded-For` is what matters.
#[must_use]
pub fn client_ip(parts: &Parts) -> String {
    let forwarded = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|first| !first.is_empty());
    if let Some(first) = forwarded {
        return first.to_string();
    }
    peer_addr(parts).map_or_else(String::new, |a| a.ip().to_string())
}

#[cfg(feature = "axum")]
fn peer_addr(parts: &Parts) -> Option<std::net::SocketAddr> {
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0)
        .or_else(|| parts.extensions.get::<std::net::SocketAddr>().copied())
}

#[cfg(not(feature = "axum"))]
fn peer_addr(parts: &Parts) -> Option<std::net::SocketAddr> {
    parts.extensions.get::<std::net::SocketAddr>().copied()
}

/// Read a single cookie off the request, or `""` if absent.
#[must_use]
pub fn cookie(parts: &Parts, name: &str) -> String {
    parts
        .headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key.trim() == name).then(|| value.trim().trim_matches('"').to_string())
        })
        .unwrap_or_default()
}

/// Read `name` out of an `application/x-www-form-urlencoded` string.
#[must_use]
pub fn form_value(encoded: &str, name: &str) -> String {
    encoded
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (percent_decode(key) == name).then(|| percent_decode(value))
        })
        .unwrap_or_default()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let decoded = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(b) = decoded {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Send a passwordless sign-in email.
///
/// # Errors
///
/// Returns [`StackureError`] on invalid input, or any transport or API failure.
pub async fn send_magic_link(
    email: &str,
    app_id: Option<&str>,
) -> Result<MagicLinkResponse, StackureError> {
    validate_email(email)?;

    let mut body = serde_json::json!({ "user_email": email });
    if let Some(id) = app_id.filter(|s| !s.is_empty()) {
        validate_uuid(id, "App ID")?;
        body["app_id"] = serde_json::Value::String(id.to_string());
    }

    let data = request(
        &Method::POST,
        "/api/public/auth/magic-link/send",
        CallOpts {
            body: Some(serde_json::to_vec(&body).unwrap_or_default()),
            ..CallOpts::default()
        },
    )
    .await?;

    serde_json::from_value(data)
        .map_err(|_| StackureError::Network("unexpected API response format".into()))
}

/// Validate the request's session against Stackure.
///
/// A request without a well-formed session token gets the sign-in URL
/// without a Stackure call.
///
/// Most callers want [`crate::verify`] or [`crate::auth`].
///
/// # Errors
///
/// Returns [`StackureError`] on invalid input, or any transport or API failure.
pub async fn validate_session(app_id: &str, parts: &Parts) -> Result<Session, StackureError> {
    validate_token(app_id, &cookie(parts, SESSION_COOKIE), parts).await
}

/// Validate an explicit session `token` for the browser that sent `parts`.
///
/// # Errors
///
/// Returns [`StackureError`] on invalid input, or any transport or API failure.
pub async fn validate_token(
    app_id: &str,
    token: &str,
    parts: &Parts,
) -> Result<Session, StackureError> {
    validate_uuid(app_id, "App ID")?;

    if !is_uuid(token) {
        return Ok(Session {
            sign_in_url: format!("{}/sign-in/magic-link?app_id={app_id}", base_url()),
            ..Session::default()
        });
    }

    let data = request(
        &Method::GET,
        "/api/public/auth/session/validate",
        CallOpts {
            query: Some(format!("app_id={app_id}")),
            token,
            ua: parts
                .headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            ip: &client_ip(parts),
            ..CallOpts::default()
        },
    )
    .await?;

    serde_json::from_value(data)
        .map_err(|_| StackureError::Network("unexpected API response format".into()))
}
