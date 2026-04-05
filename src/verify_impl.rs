//! Framework-agnostic authentication verification.

use crate::client::Client;
use crate::types::{VerifyError, VerifyResult};

/// Verify authentication for an incoming request.
///
/// Validates the session and optionally enforces role requirements. Returns a
/// structured [`VerifyResult`] without panicking, so you decide what happens next.
///
/// # Arguments
///
/// * `app_id` - Your Stackure application UUID.
/// * `cookies` - Raw `Cookie` header value from the incoming HTTP request.
/// * `roles` - Optional list of acceptable role names. The user must hold at
///   least one.
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
pub async fn verify(
    app_id: &str,
    cookies: Option<&str>,
    roles: Option<&[&str]>,
) -> VerifyResult {
    let client = Client::with_defaults();
    verify_with_client(&client, app_id, cookies, roles).await
}

/// Verify authentication using a specific [`Client`] instance.
pub async fn verify_with_client(
    client: &Client,
    app_id: &str,
    cookies: Option<&str>,
    roles: Option<&[&str]>,
) -> VerifyResult {
    match client.validate_session(app_id, cookies).await {
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
            if let Some(required_roles) = roles {
                if !required_roles.is_empty() {
                    let user_roles = &user.user_roles;
                    let has_role = required_roles
                        .iter()
                        .any(|r| user_roles.iter().any(|ur| ur == r));
                    if !has_role {
                        let role_list = required_roles.join(", ");
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
            }
            VerifyResult {
                authenticated: true,
                user: Some(user),
                error: None,
            }
        }
        Err(e) => {
            eprintln!("Stackure verification error: {e}");
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
