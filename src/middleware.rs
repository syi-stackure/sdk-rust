//! Session verification and the tower authentication middleware.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Limited};
use tower::{Layer, Service};

use crate::client::{
    SESSION_COOKIE, TOKEN_PARAM, base_url, form_value, origin, sign_out, validate_mcp,
    validate_session, validate_token,
};
use crate::types::{User, VerifyError, VerifyResult};

/// Verify a request without returning an error.
///
/// Callers inspect `authenticated` and decide how to respond. Transport and
/// API failures come back as a 500 result.
///
/// # Example
///
/// ```no_run
/// # async fn example(parts: &http::request::Parts) {
/// let result = stackure::verify("7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071", parts, &["can_approve_invoice"]).await;
/// if result.authenticated {
///     println!("{}", result.user.unwrap().user_email);
/// }
/// # }
/// ```
pub async fn verify(app_id: &str, parts: &Parts, permissions: &[&str]) -> VerifyResult {
    let session = match validate_session(app_id, parts).await {
        Ok(session) => session,
        Err(e) => {
            eprintln!("stackure: verification error: {e}");
            return VerifyResult {
                error: Some(VerifyError {
                    code: 500,
                    message: "Authentication verification failed".into(),
                    sign_in_url: String::new(),
                }),
                ..VerifyResult::default()
            };
        }
    };

    let Some(user) = session.user.filter(|_| session.authenticated) else {
        return VerifyResult {
            error: Some(VerifyError {
                code: 401,
                message: "Valid authentication required".into(),
                sign_in_url: session.sign_in_url,
            }),
            ..VerifyResult::default()
        };
    };

    if !permissions.is_empty()
        && !permissions
            .iter()
            .any(|p| user.user_permissions.iter().any(|held| held == p))
    {
        let list = permissions.join(", ");
        return VerifyResult {
            user: Some(user),
            error: Some(VerifyError {
                code: 403,
                message: format!("Requires one of: {list}"),
                sign_in_url: String::new(),
            }),
            ..VerifyResult::default()
        };
    }

    VerifyResult {
        authenticated: true,
        user: Some(user),
        error: None,
    }
}

/// The user attached by [`auth`] or [`mcp`], or `None` if the request was not
/// authenticated. In axum you can also take an `Extension<User>` directly.
#[must_use]
pub fn user_from_request(parts: &Parts) -> Option<&User> {
    parts.extensions.get::<User>()
}

fn is_https(parts: &Parts) -> bool {
    parts.uri.scheme_str() == Some("https")
        || parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

fn cookie_header(value: &str, secure: bool, max_age: Option<i32>) -> String {
    let mut parts = format!("{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        parts.push_str("; Secure");
    }
    if let Some(age) = max_age {
        use std::fmt::Write as _;
        let _ = write!(parts, "; Max-Age={age}");
    }
    parts
}

const MAX_HANDOFF_BODY: usize = 4096;
const SESSION_MAX_AGE: i32 = 604_800;

fn self_url(parts: &Parts) -> &str {
    parts
        .uri
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str)
        .filter(|p| p.starts_with('/') && !p.starts_with("//") && !p.starts_with("/\\"))
        .unwrap_or("/")
}

fn wants_form_token(parts: &Parts) -> bool {
    parts.method == http::Method::POST
        && parts.headers.get("origin").and_then(|v| v.to_str().ok()) == Some(origin().as_str())
        && parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
}

fn accepts_html(parts: &Parts) -> bool {
    let accept = parts
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    accept.contains("text/html") && !accept.contains("application/json")
}

fn error_body(error: &VerifyError) -> Bytes {
    let label = match error.code {
        401 => "Unauthorized",
        403 => "Forbidden",
        _ => "Error",
    };
    Bytes::from(
        serde_json::json!({
            "error": label,
            "message": error.message,
            "sign_in_url": error.sign_in_url,
        })
        .to_string(),
    )
}

fn mcp_url(parts: &Parts) -> String {
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.uri.authority().map(http::uri::Authority::as_str))
        .unwrap_or_default();
    let scheme = if is_https(parts) { "https" } else { "http" };
    #[cfg(feature = "axum")]
    let path = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or(parts.uri.path(), |u| u.0.path());
    #[cfg(not(feature = "axum"))]
    let path = parts.uri.path();
    format!("{scheme}://{host}{path}")
}

fn mcp_error<B: From<Bytes>>(
    status: StatusCode,
    error: &str,
    challenge: Option<&str>,
) -> Response<B> {
    let mut response = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some(challenge) = challenge {
        response = response.header(
            "www-authenticate",
            HeaderValue::from_str(challenge)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or(HeaderValue::from_static("Bearer")),
        );
    }
    response
        .body(B::from(Bytes::from(
            serde_json::json!({ "error": error }).to_string(),
        )))
        .expect("error response is always valid")
}

fn same_origin_post(parts: &Parts) -> bool {
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .map(|v| v.to_str().unwrap_or_default())
    };
    let repeated = |name: &str| parts.headers.get_all(name).iter().nth(1).is_some();
    if parts.method != http::Method::POST
        || ["sec-fetch-site", "origin", "host"]
            .into_iter()
            .any(repeated)
    {
        return false;
    }
    if let Some(site) = header("sec-fetch-site") {
        return site == "same-origin";
    }
    let host = header("host").or_else(|| parts.uri.authority().map(http::uri::Authority::as_str));
    header("origin")
        .and_then(|origin| origin.split_once("://"))
        .zip(host)
        .is_some_and(|((scheme, origin), host)| {
            (scheme == "https" || !is_https(parts))
                && !host.is_empty()
                && origin.eq_ignore_ascii_case(host)
        })
}

/// End the user's access everywhere with a server-side call to Stackure,
/// clear the app's session cookie and redirect to Stackure.
///
/// Mount it for every method on the logout path. Trigger it with a form or
/// button that POSTs from the app's own page; a link or any other request is
/// sent to Stackure's sign-out page, where the user confirms, with no call
/// made and the cookie left in place.
///
/// A request counts as coming from the app's own page when it is a POST with
/// `Sec-Fetch-Site: same-origin` or, when that header is absent, with an
/// `Origin` whose host and port match `Host` and whose scheme is `https` if
/// the request arrived over HTTPS. A request that repeats `Sec-Fetch-Site`,
/// `Origin` or `Host` never counts.
///
/// If the call fails, the redirect goes to Stackure's sign-out page instead,
/// where the user can finish signing out.
///
/// Asynchronous: awaiting it yields the 303 [`Response`], never an error.
///
/// # Example
///
/// ```no_run
/// # use axum::{Router, routing::any};
/// async fn logout(parts: http::request::Parts) -> axum::response::Response {
///     stackure::logout(&parts).await
/// }
///
/// let app: Router = Router::new().route("/logout", any(logout));
/// ```
#[must_use]
pub async fn logout<B: Default>(parts: &Parts) -> Response<B> {
    let mut response = Response::builder().status(StatusCode::SEE_OTHER);
    let mut path = "/signout";
    if same_origin_post(parts) {
        match sign_out(parts).await {
            Ok(()) => path = "/",
            Err(e) => eprintln!("stackure: sign-out error: {e}"),
        }
        response = response.header("set-cookie", cookie_header("", is_https(parts), Some(0)));
    }
    response
        .header("location", format!("{}{path}", base_url()))
        .body(B::default())
        .expect("logout response is always valid")
}

/// Middleware that enforces authentication, for any tower stack — axum,
/// tonic, or hyper.
///
/// Completes Stackure's sign-in handoff by validating the posted
/// `session_token` and storing it as a cookie on your domain. On success the
/// user is inserted into the request extensions (read it back with
/// [`user_from_request`]). Browser requests get redirected to sign-in on 401;
/// API requests get JSON.
///
/// # Example
///
/// ```no_run
/// # use axum::{Router, routing::get};
/// # let app: Router = Router::new().route("/admin", get(|| async {}));
/// let app = app.layer(stackure::auth(
///     "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071",
///     &["can_approve_invoice"],
/// ));
/// ```
#[must_use]
pub fn auth(app_id: &str, permissions: &[&str]) -> AuthLayer {
    AuthLayer {
        app_id: Arc::from(app_id),
        permissions: permissions.iter().map(|p| (*p).to_string()).collect(),
        mcp: false,
    }
}

/// Middleware that protects an MCP route, for any tower stack — axum, tonic,
/// or hyper.
///
/// AI clients sign users in through Stackure and send the credential it issues
/// as `Authorization: Bearer`. The layer checks that credential against
/// Stackure on every request, with the same app secret as [`auth`]; cookies
/// are ignored. On success the user is inserted into the request extensions,
/// exactly as [`auth`] does. Every other answer is JSON, never a redirect and
/// never a cookie: 401 with the `WWW-Authenticate` challenge from Stackure
/// when not signed in, 403 when a required permission is missing, 503 when
/// the check itself fails.
///
/// The MCP endpoint must be served from the same site as the app's registered
/// URL unless an MCP URL is set for the app in Stackure.
///
/// # Example
///
/// ```no_run
/// # use axum::{Router, routing::any};
/// # let app: Router = Router::new().route("/mcp", any(|| async {}));
/// let app = app.layer(stackure::mcp("7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071", &[]));
/// ```
#[must_use]
pub fn mcp(app_id: &str, permissions: &[&str]) -> AuthLayer {
    AuthLayer {
        mcp: true,
        ..auth(app_id, permissions)
    }
}

/// The tower [`Layer`] returned by [`auth`] and [`mcp`].
#[derive(Clone, Debug)]
pub struct AuthLayer {
    app_id: Arc<str>,
    permissions: Arc<[String]>,
    mcp: bool,
}

impl<S> Layer<S> for AuthLayer {
    type Service = Auth<S>;

    fn layer(&self, inner: S) -> Auth<S> {
        Auth {
            inner,
            app_id: self.app_id.clone(),
            permissions: self.permissions.clone(),
            mcp: self.mcp,
        }
    }
}

/// The tower [`Service`] produced by [`AuthLayer`].
#[derive(Clone, Debug)]
pub struct Auth<S> {
    inner: S,
    app_id: Arc<str>,
    permissions: Arc<[String]>,
    mcp: bool,
}

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

impl<S, ReqB, ResB> Service<Request<ReqB>> for Auth<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqB: Body<Data = Bytes> + From<Bytes> + Send + 'static,
    ReqB::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResB: From<Bytes> + Send + 'static,
{
    type Response = Response<ResB>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let app_id = self.app_id.clone();
        let permissions = self.permissions.clone();
        let mcp = self.mcp;

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            if mcp {
                let session = match validate_mcp(&app_id, &mcp_url(&parts), &parts).await {
                    Ok(session) => session,
                    Err(e) => {
                        eprintln!("stackure: verification error: {e}");
                        return Ok(mcp_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "unavailable",
                            None,
                        ));
                    }
                };
                let Some(user) = session.user.filter(|_| session.authenticated) else {
                    return Ok(mcp_error(
                        StatusCode::UNAUTHORIZED,
                        "unauthorized",
                        Some(&session.www_authenticate),
                    ));
                };
                if !permissions.is_empty()
                    && !permissions
                        .iter()
                        .any(|p| user.user_permissions.contains(p))
                {
                    return Ok(mcp_error(StatusCode::FORBIDDEN, "forbidden", None));
                }
                parts.extensions.insert(user);
                return inner.call(Request::from_parts(parts, body)).await;
            }

            let mut token = String::new();
            let body = if wants_form_token(&parts) {
                let bytes = Limited::new(body, MAX_HANDOFF_BODY)
                    .collect()
                    .await
                    .map(http_body_util::Collected::to_bytes)
                    .unwrap_or_default();
                token = form_value(&String::from_utf8_lossy(&bytes), TOKEN_PARAM);
                ReqB::from(bytes)
            } else {
                body
            };

            if !token.is_empty()
                && validate_token(&app_id, &token, &parts)
                    .await
                    .is_ok_and(|s| s.authenticated)
            {
                return Ok(Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header("location", self_url(&parts))
                    .header(
                        "set-cookie",
                        cookie_header(&token, is_https(&parts), Some(SESSION_MAX_AGE)),
                    )
                    .body(ResB::from(Bytes::new()))
                    .expect("handoff response is always valid"));
            }

            let permissions: Vec<&str> = permissions.iter().map(String::as_str).collect();
            let result = verify(&app_id, &parts, &permissions).await;

            if let Some(error) = result.error.filter(|_| !result.authenticated) {
                if error.code == 401 && accepts_html(&parts) && !error.sign_in_url.is_empty() {
                    return Ok(Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", error.sign_in_url)
                        .body(ResB::from(Bytes::new()))
                        .expect("redirect response is always valid"));
                }
                return Ok(Response::builder()
                    .status(StatusCode::from_u16(error.code).unwrap_or(StatusCode::UNAUTHORIZED))
                    .header("content-type", "application/json")
                    .body(ResB::from(error_body(&error)))
                    .expect("error response is always valid"));
            }

            if let Some(user) = result.user {
                parts.extensions.insert(user);
            }
            inner.call(Request::from_parts(parts, body)).await
        })
    }
}
