//! Fixed values, and the environment the SDK reads once on first use.

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use crate::errors::StackureError;
use crate::validation::{is_loopback_host, validate_uuid};

pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_RETRIES: u32 = 1;
pub(crate) const RETRY_DELAY: Duration = Duration::from_millis(500);
pub(crate) const MAX_EVENTS: u32 = 100;
pub(crate) const MAX_HANDOFF_BODY: usize = 4096;

/// Name of the session cookie the SDK reads and writes.
pub const SESSION_COOKIE: &str = "stackure_session";
/// Name of the sign-in handoff parameter Stackure sends back.
pub const TOKEN_PARAM: &str = "session_token";
pub(crate) const PLATFORM_COOKIE: &str = "session";
pub(crate) const CODE_COOKIE: &str = "stackure_code";
pub(crate) const VERIFIER_COOKIE: &str = "stackure_verifier";
pub(crate) const CODE_PARAM: &str = "stackure_code";
pub(crate) const SESSION_MAX_AGE: i32 = 604_800;
pub(crate) const CODE_MAX_AGE: i32 = 60;
pub(crate) const VERIFIER_MAX_AGE: i32 = 900;
pub(crate) const VERIFIER_BYTES: usize = 32;

pub(crate) const MAGIC_LINK_PATH: &str = "/api/public/auth/magic-link/send";
pub(crate) const VALIDATE_PATH: &str = "/api/public/auth/session/validate";
pub(crate) const EXCHANGE_PATH: &str = "/api/public/auth/session/exchange";
pub(crate) const DIRECTORY_USERS_PATH: &str = "/api/public/directory/users";
pub(crate) const DIRECTORY_TEAMS_PATH: &str = "/api/public/directory/teams";
pub(crate) const EVENTS_PATH: &str = "/api/public/events";
pub(crate) const SIGN_OUT_PATH: &str = "/api/public/auth/sign-out";
pub(crate) const SIGN_IN_PAGE: &str = "/sign-in/magic-link";
pub(crate) const SIGN_OUT_PAGE: &str = "/signout";
pub(crate) const HOME_PAGE: &str = "/";

const INVALID_BASE_URL: &str =
    "invalid STACKURE_BASE_URL format (must be an https URL, or http on localhost or 127.0.0.1)";

struct Env {
    base_url: Result<String, StackureError>,
    origin: String,
    app_id: Result<String, StackureError>,
    app_secret: Result<String, StackureError>,
}

fn var(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn required(key: &str) -> Result<String, StackureError> {
    var(key).ok_or_else(|| StackureError::Validation(format!("{key} is not set")))
}

fn origin_of(base: &str) -> Option<String> {
    if base.contains(['?', '#']) {
        return None;
    }
    let uri = base.parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?.as_str();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let allowed = scheme == "https" || (scheme == "http" && is_loopback_host(authority));
    let port = match authority.rsplit_once(':') {
        Some((_, port)) if !port.ends_with(']') => port.is_empty() || port.parse::<u16>().is_ok(),
        _ => true,
    };
    (allowed && port && uri.host().is_some_and(|h| !h.is_empty()))
        .then(|| format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

fn read_base_url() -> (Result<String, StackureError>, String) {
    let raw = var("STACKURE_BASE_URL")
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    if raw.is_empty() {
        let unset = StackureError::Validation("STACKURE_BASE_URL is not set".into());
        return (Err(unset), String::new());
    }
    match origin_of(&raw) {
        Some(origin) => (Ok(raw), origin),
        None => (
            Err(StackureError::Validation(INVALID_BASE_URL.into())),
            String::new(),
        ),
    }
}

fn read() -> Env {
    let (base_url, origin) = read_base_url();
    let app_id =
        required("STACKURE_APP_ID").and_then(|v| validate_uuid(&v, "STACKURE_APP_ID").map(|()| v));
    Env {
        base_url,
        origin,
        app_id,
        app_secret: required("STACKURE_APP_SECRET"),
    }
}

fn loaded() -> &'static Env {
    static ENV: OnceLock<Env> = OnceLock::new();
    ENV.get_or_init(read)
}

/// The `STACKURE_BASE_URL` the SDK read on first use, without its trailing
/// `/`. Empty when unset, when it isn't an `https` URL (`http` is accepted
/// only on `localhost` or `127.0.0.1`) or when it has a query or fragment.
#[must_use]
pub fn base_url() -> String {
    loaded().base_url.as_deref().unwrap_or_default().to_string()
}

pub(crate) fn required_base_url() -> Result<&'static str, StackureError> {
    loaded().base_url.as_deref().map_err(StackureError::clone)
}

pub(crate) fn origin() -> &'static str {
    &loaded().origin
}

pub(crate) fn app_id() -> Result<&'static str, StackureError> {
    loaded().app_id.as_deref().map_err(StackureError::clone)
}

pub(crate) fn app_secret() -> Result<&'static str, StackureError> {
    loaded().app_secret.as_deref().map_err(StackureError::clone)
}
