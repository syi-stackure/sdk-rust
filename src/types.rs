//! Types returned by the Stackure SDK.

use serde::{Deserialize, Serialize};

/// An authenticated Stackure user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user.
    pub user_id: String,
    /// User's email address.
    pub user_email: String,
    /// User's first name.
    pub user_first_name: String,
    /// User's last name.
    pub user_last_name: String,
    /// Permissions granted to the user for the current app.
    #[serde(default)]
    pub user_permissions: Vec<String>,
}

/// Successful [`crate::send_magic_link`] response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicLinkResponse {
    /// Human-readable confirmation from the API.
    pub message: String,
}

/// Why a [`crate::verify`] call did not authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyError {
    /// HTTP status code: 401, 403, or 500.
    pub code: u16,
    /// Human-readable message.
    pub message: String,
    /// Where to send an unauthenticated browser to sign in.
    #[serde(default)]
    pub sign_in_url: String,
}

/// Outcome of a [`crate::verify`] call.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the request carries a valid session.
    pub authenticated: bool,
    /// The user, when authenticated (also set on a 403).
    pub user: Option<User>,
    /// Populated when `authenticated` is `false`.
    pub error: Option<VerifyError>,
}

/// Raw [`crate::validate_session`] response.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Session {
    /// Whether Stackure recognised the session.
    #[serde(default)]
    pub authenticated: bool,
    /// The user, when authenticated.
    #[serde(default)]
    pub user: Option<User>,
    /// Where to send the browser to sign in, when not.
    #[serde(default)]
    pub sign_in_url: String,
}
