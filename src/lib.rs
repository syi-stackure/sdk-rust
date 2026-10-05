//! Stackure is the Rust SDK for the Stackure authentication API.
//!
//! Stackure provides passwordless B2B authentication. This SDK wraps the
//! public API behind eight free functions and a tower middleware.
//!
//! # Quickstart
//!
//! Protect an axum app:
//!
//! ```no_run
//! # use axum::{Router, routing::get};
//! # let app: Router = Router::new().route("/admin", get(|| async {}));
//! let app = app.layer(stackure::auth(&["can_approve_invoice"]));
//! ```
//!
//! The layer works in any tower stack — axum, tonic, or hyper.
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
//! let result = stackure::verify(parts, &[]).await;
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
//! let response = stackure::send_magic_link("user@example.com").await;
//! # }
//! ```
//!
//! Log the user out, ending their access everywhere. Mount it for every method
//! on the logout path. Trigger it with a form or button that POSTs from the
//! app's own page; a link or any other request is sent to Stackure's sign-out
//! page, where the user confirms. Awaiting it yields the redirect response,
//! never an error:
//!
//! ```no_run
//! # use axum::{Router, routing::any};
//! async fn logout(parts: http::request::Parts) -> axum::response::Response {
//!     stackure::logout(&parts).await
//! }
//!
//! let app: Router = Router::new().route("/logout", any(logout));
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
//! # MCP
//!
//! Protect an MCP route:
//!
//! ```no_run
//! # use axum::{Router, routing::any};
//! # let app: Router = Router::new().route("/mcp", any(|| async {}));
//! let app = app.layer(stackure::mcp(&[]));
//! ```
//!
//! AI clients such as Claude, Claude Code, VS Code and Cursor sign users in
//! through Stackure. This one line checks every MCP request in real time with
//! the same app secret; there is no extra setup. The MCP endpoint must be
//! served from the same site as the app's registered URL unless an MCP URL is
//! set for the app in Stackure.
//!
//! The [`mcp`] layer reads only `Authorization: Bearer` and ignores cookies.
//! It attaches the user exactly as [`auth`] does, and otherwise answers in
//! JSON, never with a redirect or a cookie: 401 with a `WWW-Authenticate`
//! header when not signed in, 403 when a required permission is missing, 503
//! when the check itself fails.
//!
//! # Configuration
//!
//! `STACKURE_APP_ID` must be set to the app's UUID, shown on the app page in
//! Stackure, and `STACKURE_APP_SECRET` to the app secret shown when the app
//! was registered (or last rotated) in Stackure. The secret is sent as the
//! `X-App-Secret` header on every call except the sign-out made by
//! [`logout`], which carries the user's session token instead. The first call
//! that needs either fails with [`StackureError::Validation`] when it is
//! unset, or when `STACKURE_APP_ID` is not a UUID. `STACKURE_BASE_URL`
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
//! Every function except [`verify`] and [`logout`] returns [`StackureError`].
//! [`logout`] never returns an error: a failed sign-out call still ends in a
//! redirect. Match on the variant, or call [`StackureError::code`] for the same
//! lowercase category string the other Stackure SDKs expose as `.code`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;

pub mod errors;
pub mod middleware;
pub mod types;
pub mod validation;

pub use client::{SESSION_COOKIE, TOKEN_PARAM, base_url, send_magic_link, validate_session};
pub use errors::StackureError;
pub use middleware::{Auth, AuthLayer, auth, logout, mcp, user_from_request, verify};
pub use types::{MagicLinkResponse, Session, User, VerifyError, VerifyResult};
