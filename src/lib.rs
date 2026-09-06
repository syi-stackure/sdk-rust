//! Stackure is the Rust SDK for the Stackure authentication API.
//!
//! Stackure provides passwordless B2B authentication. This SDK wraps the
//! public API behind five free functions and a tower middleware.
//!
//! # Quickstart
//!
//! Protect an axum app:
//!
//! ```no_run
//! # use axum::{Router, routing::get};
//! # let app: Router = Router::new().route("/admin", get(|| async {}));
//! let app = app.layer(stackure::auth(APP_ID, &["view_any_app"]));
//! # const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
//! ```
//!
//! `APP_ID` is the app's UUID as registered in Stackure. The layer works in
//! any tower stack — axum, tonic, or hyper.
//!
//! Access the authenticated user inside a handler:
//!
//! ```no_run
//! # fn example(parts: &http::request::Parts) {
//! let user = stackure::user_from_request(parts);
//! # }
//! ```
//!
//! Manual verification without middleware:
//!
//! ```no_run
//! # async fn example(parts: &http::request::Parts) {
//! # const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
//! let result = stackure::verify(APP_ID, parts, &[]).await;
//! if result.authenticated {
//!     // use result.user
//! }
//! # }
//! ```
//!
//! Send a magic-link email:
//!
//! ```no_run
//! # async fn example() {
//! # const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
//! let response = stackure::send_magic_link("user@example.com", Some(APP_ID)).await;
//! # }
//! ```
//!
//! Log the user out:
//!
//! ```no_run
//! # fn example(parts: &http::request::Parts) -> http::Response<axum::body::Body> {
//! stackure::logout(parts)
//! # }
//! ```
//!
//! # Sign-in handoff
//!
//! Stackure's session cookie is scoped to the Stackure host and is never
//! visible to your app. After a successful magic-link sign-in, Stackure hands
//! the browser back to the app's registered URL with a `session_token`, either
//! as a POST form field or as a query parameter.
//!
//! The [`auth`] layer consumes both automatically: it stores the token in a
//! cookie on your own domain and redirects to the same URL with the parameter
//! stripped, so the token does not linger in the address bar.
//!
//! # Session binding
//!
//! Stackure binds each session to the browser's user agent and IP address.
//! Because the SDK validates from your server rather than the browser, it
//! forwards the original `User-Agent` and `X-Forwarded-For` on every
//! validation call. Your app must therefore see the real client IP: if it sits
//! behind a proxy or CDN, ensure that layer sets `X-Forwarded-For` correctly.
//!
//! Every request is validated against Stackure, so revoking a session takes
//! effect immediately.
//!
//! # Content negotiation
//!
//! The [`auth`] layer inspects the `Accept` header. Browser requests (`Accept:
//! text/html`) redirect to the sign-in URL on 401. API requests (`Accept:
//! application/json`) receive a JSON error body.
//!
//! # Configuration
//!
//! The SDK has no configuration API. Point it at a non-production environment
//! by setting the `STACKURE_BASE_URL` environment variable before the first
//! call.
//!
//! Retry-on-5xx (one retry after 500ms) and the 2-second request timeout are
//! hard-coded. Timeouts are never retried.
//!
//! # Errors
//!
//! Every function except [`verify`] returns [`StackureError`]. Match on the
//! variant, or call [`StackureError::code`] for the same lowercase category
//! string the other Stackure SDKs expose as `.code`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;

pub mod errors;
pub mod middleware;
pub mod types;
pub mod validation;

pub use client::{SESSION_COOKIE, TOKEN_PARAM, base_url, send_magic_link, validate_session};
pub use errors::StackureError;
pub use middleware::{Auth, AuthLayer, auth, logout, user_from_request, verify};
pub use types::{MagicLinkResponse, Session, User, VerifyError, VerifyResult};
