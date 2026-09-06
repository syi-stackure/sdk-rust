//! Session verification and the tower authentication middleware.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::request::Parts;
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::BodyExt;
use tower::{Layer, Service};

use crate::client::{
    SESSION_COOKIE, TOKEN_PARAM, base_url, cookie, form_value, query_param, validate_session,
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

/// The user attached by [`auth`], or `None` if the request was not
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

fn clean_url(parts: &Parts) -> String {
    let path = parts.uri.path();
    let query: Vec<&str> = parts
        .uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| {
            !pair.is_empty() && pair.split_once('=').is_none_or(|(k, _)| k != TOKEN_PARAM)
        })
        .collect();

    if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", query.join("&"))
    }
}

fn wants_form_token(parts: &Parts) -> bool {
    parts.method == http::Method::POST
        && cookie(parts, SESSION_COOKIE).is_empty()
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

/// Clear the app's session cookie and redirect to Stackure's sign-out, which
/// revokes the session.
///
/// # Example
///
/// ```no_run
/// # fn example(parts: &http::request::Parts) -> http::Response<axum::body::Body> {
/// stackure::logout(parts)
/// # }
/// ```
#[must_use]
pub fn logout<B: Default>(parts: &Parts) -> Response<B> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", format!("{}/signout", base_url()))
        .header("set-cookie", cookie_header("", is_https(parts), Some(0)))
        .body(B::default())
        .expect("logout response is always valid")
}

/// Middleware that enforces authentication, for any tower stack — axum,
/// tonic, or hyper.
///
/// Completes Stackure's sign-in handoff by storing the returned
/// `session_token` as a cookie on your domain, then stripping it from the
/// URL. On success the user is inserted into the request extensions (read it
/// back with [`user_from_request`]). Browser requests get redirected to
/// sign-in on 401; API requests get JSON.
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
    }
}

/// The tower [`Layer`] returned by [`auth`].
#[derive(Clone, Debug)]
pub struct AuthLayer {
    app_id: Arc<str>,
    permissions: Arc<[String]>,
}

impl<S> Layer<S> for AuthLayer {
    type Service = Auth<S>;

    fn layer(&self, inner: S) -> Auth<S> {
        Auth {
            inner,
            app_id: self.app_id.clone(),
            permissions: self.permissions.clone(),
        }
    }
}

/// The tower [`Service`] produced by [`AuthLayer`].
#[derive(Clone, Debug)]
pub struct Auth<S> {
    inner: S,
    app_id: Arc<str>,
    permissions: Arc<[String]>,
}

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

impl<S, ReqB, ResB> Service<Request<ReqB>> for Auth<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqB: Body<Data = Bytes> + From<Bytes> + Send + 'static,
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

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            let mut token = query_param(&parts, TOKEN_PARAM);
            let body = if !token.is_empty() || !wants_form_token(&parts) {
                body
            } else {
                let bytes = body
                    .collect()
                    .await
                    .map(http_body_util::Collected::to_bytes)
                    .unwrap_or_default();
                token = form_value(&String::from_utf8_lossy(&bytes), TOKEN_PARAM);
                ReqB::from(bytes)
            };

            if !token.is_empty() {
                return Ok(Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header("location", clean_url(&parts))
                    .header("set-cookie", cookie_header(&token, is_https(&parts), None))
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
