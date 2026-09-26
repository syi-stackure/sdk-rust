//! Stackure is the Rust SDK for the Stackure authentication API.
//!
//! Stackure provides passwordless B2B authentication. This SDK wraps the
//! public API behind seven free functions and a tower middleware.
//!
//! # Quickstart
//!
//! Protect an axum app:
//!
//! ```no_run
//! # use axum::{Router, routing::get};
//! # let app: Router = Router::new().route("/admin", get(|| async {}));
//! let app = app.layer(stackure::auth(APP_ID, &["can_approve_invoice"]));
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
//! the browser back to the app's registered URL with a `session_token` POST
//! form field: an app-scoped session token valid only for this app, accepted
//! by the validate endpoint for your app ID and never by Stackure itself.
//!
//! The [`auth`] layer consumes it automatically: it validates the token, stores
//! it in a cookie on your own domain and redirects to the same URL as a GET.
//! Invalid tokens are ignored, and handoff bodies over 4 KB are ignored (treated
//! as no token).
//!
//! # Session binding
//!
//! Sessions are not bound to the browser's user agent or IP address. The SDK
//! still forwards the original `User-Agent` and `X-Forwarded-For` on every
//! validation call, but they are informational only; validation does not
//! depend on them.
//!
//! Every request with a session token is validated against Stackure, so revoking
//! a session takes effect immediately. Requests without a well-formed token get
//! the sign-in URL without a Stackure call.
//!
//! # Content negotiation
//!
//! The [`auth`] layer inspects the `Accept` header. Browser requests (`Accept:
//! text/html`) redirect to the sign-in URL on 401. API requests (`Accept:
//! application/json`) receive a JSON error body.
//!
//! # Configuration
//!
//! `STACKURE_APP_SECRET` must be set to the app secret shown when the app was
//! registered (or last rotated) in Stackure. It is sent as the `X-App-Secret`
//! header on every call; the first call that actually reaches Stackure fails
//! with [`StackureError::Validation`] when it is unset. `STACKURE_BASE_URL`
//! overrides the API host (default `https://stackure.com`).
//!
//! A newly registered app is not usable by anyone, even its creator, until it
//! is shared with the organization or assigned to a team in Stackure. Do that
//! before testing sign-in.
//!
//! Every SDK call has one 2-second wall-clock deadline covering connect,
//! headers, body and the single retry. The SDK retries once, after 500 ms, on
//! a 5xx response or a connection failure, and only if more than 500 ms of the
//! deadline remain. A timeout, including while reading the body, surfaces as
//! [`StackureError::Timeout`] and is never retried.
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
