//! Official Stackure authentication SDK for Rust.
//!
//! Provides four free async functions: [`auth`] (not yet — framework-specific),
//! [`verify`], [`send_magic_link`], and [`logout`]. No client struct, no
//! config type, no caller-tunable knobs.
//!
//! Point at a non-production environment by setting `STACKURE_BASE_URL`
//! before the first call.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn example() {
//! let result = stackure::verify("my-app-id", Some("session=abc"), Some(&["admin"])).await;
//! if result.authenticated {
//!     println!("{:?}", result.user);
//! }
//! # }
//! ```
//!
//! # Errors
//!
//! Every fallible function returns [`StackureError`]. Match on the variant or
//! call [`StackureError::code`] for a stable lowercase category string.

mod http;
pub mod validation;

pub mod errors;
pub mod types;

pub use errors::StackureError;
pub use types::{MagicLinkResponse, User, VerifyError, VerifyResult};

/// Send a passwordless sign-in email to a user.
///
/// # Errors
///
/// Returns [`StackureError::Validation`] on malformed input, or any other
/// variant matching the wire-level failure.
pub async fn send_magic_link(
    email: &str,
    app_id: Option<&str>,
) -> Result<MagicLinkResponse, StackureError> {
    http::send_magic_link(email, app_id).await
}

/// Revoke the session represented by the given cookies.
///
/// # Errors
///
/// Returns [`StackureError::Network`] or [`StackureError::Timeout`] on
/// request failure.
pub async fn logout(cookies: Option<&str>) -> Result<(), StackureError> {
    http::logout(cookies).await
}

/// Check an incoming request's authentication state without panicking.
///
/// Returns a [`VerifyResult`] — callers inspect `authenticated` and decide how
/// to respond.
///
/// # Arguments
///
/// * `app_id` - Your Stackure application UUID.
/// * `cookies` - Raw `Cookie` header value from the incoming HTTP request.
/// * `roles` - Optional required roles; the user must hold at least one.
///
/// # Example
///
/// ```no_run
/// # async fn example() {
/// let result = stackure::verify("my-app-id", Some("session=abc"), Some(&["admin"])).await;
/// if result.authenticated {
///     let user = result.user.unwrap();
///     println!("{} {:?}", user.user_email, user.user_roles);
/// }
/// # }
/// ```
pub async fn verify(app_id: &str, cookies: Option<&str>, roles: Option<&[&str]>) -> VerifyResult {
    match http::validate_session(app_id, cookies).await {
        Ok(session) => {
            if !session.authenticated || session.user.is_none() {
                return VerifyResult {
                    authenticated: false,
                    user: None,
                    error: Some(VerifyError {
                        code: 401,
                        message: "Valid authentication required".into(),
                        sign_in_url: session.sign_in_url,
                    }),
                };
            }
            let user = session.user.unwrap();
            if let Some(required) = roles {
                if !required.is_empty()
                    && !required
                        .iter()
                        .any(|r| user.user_roles.iter().any(|ur| ur == r))
                {
                    let role_list = required.join(", ");
                    return VerifyResult {
                        authenticated: false,
                        user: Some(user),
                        error: Some(VerifyError {
                            code: 403,
                            message: format!("Requires one of: {role_list}"),
                            sign_in_url: None,
                        }),
                    };
                }
            }
            VerifyResult {
                authenticated: true,
                user: Some(user),
                error: None,
            }
        }
        Err(e) => {
            eprintln!("stackure: verification error: {e}");
            VerifyResult {
                authenticated: false,
                user: None,
                error: Some(VerifyError {
                    code: 500,
                    message: "Authentication verification failed".into(),
                    sign_in_url: None,
                }),
            }
        }
    }
}
