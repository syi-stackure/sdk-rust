//! Public types returned by the Stackure SDK.

use serde::{Deserialize, Serialize};

/// An authenticated Stackure user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user.
    pub user_id: String,
    /// User's email address.
    pub user_email: String,
    /// User's first name.
    pub user_first_name: String,
    /// User's last name.
    pub user_last_name: String,
    /// Roles assigned to the user for the current app.
    #[serde(default)]
    pub user_roles: Vec<String>,
}

/// Successful `send_magic_link` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkResponse {
    /// Human-readable confirmation from the API.
    pub message: String,
}

/// Outcome of a [`crate::verify`] call.
///
/// Exactly one of `user` or `error` is populated depending on `authenticated`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the request carries a valid session.
    pub authenticated: bool,
    /// Authenticated user (only when `authenticated` is `true`).
    pub user: Option<User>,
    /// Error context (only when `authenticated` is `false`).
    pub error: Option<VerifyError>,
}

/// Details of a failed verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyError {
    /// HTTP status code — `401`, `403`, or `500`.
    pub code: u16,
    /// Human-readable message.
    pub message: String,
    /// URL to redirect an unauthenticated user for sign-in.
    pub sign_in_url: Option<String>,
}

/// Internal session-validation response. Mapped into [`VerifyResult`] before
/// returning to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionValidationResponse {
    pub authenticated: bool,
    pub user: Option<User>,
    pub sign_in_url: Option<String>,
}

/// Internal request body for the magic-link endpoint.
#[derive(Debug, Serialize)]
pub(crate) struct SendMagicLinkRequest {
    pub user_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}
