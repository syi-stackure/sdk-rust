//! Data types returned by the Stackure SDK.

use serde::{Deserialize, Serialize};

/// Authenticated user information returned from Stackure.
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
    /// List of role names assigned to the user.
    #[serde(default)]
    pub user_roles: Vec<String>,
}

/// Response from a session validation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidationResponse {
    /// Whether the session is currently valid.
    pub authenticated: bool,
    /// Authenticated user details. Present only when `authenticated` is `true`.
    pub user: Option<User>,
    /// Redirect URL for unauthenticated users to initiate sign-in.
    pub sign_in_url: Option<String>,
}

/// Response from a magic-link send request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkResponse {
    /// Human-readable status message from the API.
    pub message: String,
    /// Verification token returned in local/testing environments only.
    pub token: Option<String>,
}

/// Result of an authentication verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the request carries a valid session.
    pub authenticated: bool,
    /// Authenticated user details. Present only when `authenticated` is `true`.
    pub user: Option<User>,
    /// Error context when `authenticated` is `false`.
    pub error: Option<VerifyError>,
}

/// Error details from a failed verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyError {
    /// HTTP status code associated with the failure.
    pub code: u16,
    /// Human-readable error message.
    pub message: String,
    /// Redirect URL for unauthenticated users.
    pub sign_in_url: Option<String>,
}

/// Internal request body for sending a magic link.
#[derive(Debug, Serialize)]
pub(crate) struct SendMagicLinkRequest {
    pub user_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}
