//! `mcp` against a local stand-in for the Stackure API.

use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use axum::body::Body;
use axum::extract::Query;
use axum::http::request::{Builder, Parts};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::{Json, Router};
use stackure::User;
use tokio::runtime::Runtime;
use tower::Service;

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
const APP_SECRET: &str = "app-secret-under-test";
const TOKEN: &str = "0b9f6c1e-5a3d-4c2b-9e8f-7a6b5c4d3e2f";
const EXPIRED: &str = "1c8e7d2f-6b4a-4d3c-8f9e-6b5a4c3d2e1f";
const UNAVAILABLE: &str = "2d7f8e3a-7c5b-4e4d-a0af-5c4b3d2e1f0a";
const BARE: &str = "3e8a9f4b-8d6c-4f5e-b1b0-4d3c2e1f0a9b";
const REFUSED: &str = "4f9b0a5c-9e7d-4a6f-82c1-3e2d1f0a9b8c";
const THROTTLED: &str = "5a0c1b6d-0f8e-4b7a-93d2-2f1e0a9b8c7d";
const REJECTED: &str = "6b1d2c7e-1a9f-4c8b-a4e3-1a0f9b8c7d6e";
const GARBLED: &str = "7c2e3d8f-2b0a-4d9c-b5f4-0b1a2c3d4e5f";
const MCP_URL: &str = "http://app.example.com/mcp";
const CHALLENGE: &str = r#"Bearer resource_metadata="https://stackure.example/.well-known/oauth-protected-resource/mcp/7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071?resource=http%3A%2F%2Fapp.example.com%2Fmcp""#;

#[derive(Debug, PartialEq)]
struct Call {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    authorization: String,
    app_secret: String,
    cookie: String,
}

fn validate_call(mcp: &str, authorization: &str) -> Call {
    Call {
        method: "GET".into(),
        path: "/api/public/auth/session/validate".into(),
        query: vec![("app_id".into(), APP_ID.into()), ("mcp".into(), mcp.into())],
        authorization: authorization.into(),
        app_secret: APP_SECRET.into(),
        cookie: String::new(),
    }
}

fn user() -> User {
    User {
        user_id: "8d3f4e9a-3c1b-4eab-86a5-1c2b3d4e5f6a".into(),
        account_id: "9e4a5f0b-4d2c-4fbc-97b6-2d3c4e5f6a7b".into(),
        user_email: "ada@example.com".into(),
        user_first_name: "Ada".into(),
        user_last_name: "Lovelace".into(),
        user_permissions: vec!["can_read_reports".into()],
    }
}

static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

fn recorded() -> MutexGuard<'static, Vec<Call>> {
    CALLS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Like Stackure, the stand-in takes the token from the session cookie first
/// and from `Authorization: Bearer` second.
async fn api(
    method: Method,
    uri: Uri,
    Query(query): Query<Vec<(String, String)>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let authorization = header("authorization");
    let cookie = header("cookie");
    let token = cookie
        .strip_prefix("session=")
        .or_else(|| authorization.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    recorded().push(Call {
        method: method.to_string(),
        path: uri.path().into(),
        query,
        authorization,
        app_secret: header("x-app-secret"),
        cookie,
    });
    match token.as_str() {
        TOKEN => Json(serde_json::json!({ "authenticated": true, "user": user() })).into_response(),
        BARE => r#"{"authenticated":false}"#.into_response(),
        GARBLED => "<html>".into_response(),
        REFUSED => (
            StatusCode::UNAUTHORIZED,
            r#"{"error":"Invalid app secret"}"#,
        )
            .into_response(),
        THROTTLED => StatusCode::TOO_MANY_REQUESTS.into_response(),
        REJECTED => StatusCode::BAD_REQUEST.into_response(),
        UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => Json(serde_json::json!({
            "authenticated": false,
            "sign_in_url": format!("https://stackure.example/sign-in/magic-link?app_id={APP_ID}"),
            "www_authenticate": CHALLENGE,
        }))
        .into_response(),
    }
}

struct Platform {
    runtime: Runtime,
    base: String,
}

fn platform() -> &'static Platform {
    static PLATFORM: OnceLock<Platform> = OnceLock::new();
    PLATFORM.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        // SAFETY: every test holds `serial` by the time it gets here, and the
        // runtime's threads do not exist yet, so nothing else is reading the
        // environment.
        unsafe {
            std::env::set_var("STACKURE_BASE_URL", &base);
            std::env::set_var("STACKURE_APP_ID", APP_ID);
            std::env::set_var("STACKURE_APP_SECRET", APP_SECRET);
        }
        let runtime = Runtime::new().unwrap();
        runtime.spawn(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, Router::new().fallback(api))
                .await
                .unwrap();
        });
        Platform { runtime, base }
    })
}

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn base() -> String {
    let _serial = serial();
    platform().base.clone()
}

async fn tool(parts: Parts) -> Json<Option<User>> {
    Json(stackure::user_from_request(&parts).cloned())
}

fn send(permissions: &[&str], request: Request<Body>) -> (Response<String>, Vec<Call>) {
    let _serial = serial();
    let platform = platform();
    recorded().clear();

    let mut app = Router::new()
        .fallback(tool)
        .layer(stackure::mcp(permissions));
    let task = platform.runtime.spawn(async move {
        let (parts, body) = app.call(request).await.unwrap().into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        Response::from_parts(parts, String::from_utf8(body.to_vec()).unwrap())
    });
    let response = platform.runtime.block_on(task).unwrap();
    (response, std::mem::take(&mut *recorded()))
}

fn mcp(permissions: &[&str], request: Builder) -> (Response<String>, Vec<Call>) {
    send(permissions, request.body(Body::empty()).unwrap())
}

fn mcp_request() -> Builder {
    Request::post("/mcp").header("host", "app.example.com")
}

fn with_bearer(token: &str) -> Builder {
    mcp_request().header("authorization", format!("Bearer {token}"))
}

fn assert_attached(response: &Response<String>, case: &str) {
    assert_eq!(response.status(), StatusCode::OK, "{case}");
    assert_eq!(
        serde_json::from_str::<Option<User>>(response.body()).unwrap(),
        Some(user()),
        "{case}"
    );
}

fn assert_answered(response: &Response<String>, status: StatusCode, error: &str, case: &str) {
    assert_eq!(response.status(), status, "{case}");
    assert_eq!(
        response.headers()["content-type"],
        "application/json",
        "{case}"
    );
    assert_eq!(
        response.body(),
        &format!(r#"{{"error":"{error}"}}"#),
        "{case}"
    );
    assert!(!response.headers().contains_key("location"), "{case}");
    assert!(!response.headers().contains_key("set-cookie"), "{case}");
    assert_eq!(
        response.headers().contains_key("www-authenticate"),
        status == StatusCode::UNAUTHORIZED,
        "{case}"
    );
}

fn assert_challenged(response: &Response<String>, case: &str) {
    assert_answered(response, StatusCode::UNAUTHORIZED, "unauthorized", case);
    assert_eq!(response.headers()["www-authenticate"], CHALLENGE, "{case}");
}

#[test]
fn valid_bearer_is_validated_without_the_cookie_and_the_user_attached() {
    let (response, calls) = mcp(
        &[],
        with_bearer(TOKEN).header("cookie", format!("session={EXPIRED}")),
    );

    assert_eq!(calls, [validate_call(MCP_URL, &format!("Bearer {TOKEN}"))]);
    assert_attached(&response, "");
}

#[test]
fn bearer_scheme_is_case_insensitive() {
    for scheme in ["bearer", "BEARER", "bEaReR"] {
        let (response, calls) = mcp(
            &[],
            mcp_request().header("authorization", format!("{scheme} {TOKEN}")),
        );

        assert_eq!(
            calls,
            [validate_call(MCP_URL, &format!("Bearer {TOKEN}"))],
            "{scheme}"
        );
        assert_attached(&response, scheme);
    }
}

#[test]
fn missing_or_malformed_bearer_is_validated_without_authorization_and_challenged() {
    for request in [
        mcp_request(),
        mcp_request().header("authorization", "Bearer not-a-token"),
        mcp_request().header("authorization", format!("Bearer {TOKEN}0")),
        mcp_request().header("authorization", format!("Bearer {TOKEN} {TOKEN}")),
        mcp_request().header("authorization", "Bearer"),
        mcp_request().header("authorization", TOKEN),
        mcp_request().header("authorization", format!("Basic {TOKEN}")),
        mcp_request().header("authorization", format!("Bearer{TOKEN}")),
    ] {
        let case = format!("{request:?}");
        let (response, calls) = mcp(&[], request.header("accept", "text/html"));

        assert_eq!(calls, [validate_call(MCP_URL, "")], "{case}");
        assert_challenged(&response, &case);
    }
}

#[test]
fn rejected_bearer_is_challenged() {
    let (response, calls) = mcp(&[], with_bearer(EXPIRED));

    assert_eq!(
        calls,
        [validate_call(MCP_URL, &format!("Bearer {EXPIRED}"))]
    );
    assert_challenged(&response, "");
}

#[test]
fn session_cookie_without_bearer_is_ignored() {
    for cookie in [
        format!("session={TOKEN}"),
        format!("theme=dark; session={TOKEN}"),
    ] {
        let (response, calls) = mcp(&[], mcp_request().header("cookie", &cookie));

        assert_eq!(calls, [validate_call(MCP_URL, "")], "{cookie}");
        assert_challenged(&response, &cookie);
    }
}

#[test]
fn sign_in_handoff_is_not_consumed() {
    let request = mcp_request()
        .header("origin", base())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("session_token={TOKEN}")))
        .unwrap();
    let (response, calls) = send(&[], request);

    assert_eq!(calls, [validate_call(MCP_URL, "")]);
    assert_challenged(&response, "");
}

#[test]
fn challenge_is_bare_bearer_when_stackure_sends_none() {
    let (response, calls) = mcp(&[], with_bearer(BARE));

    assert_eq!(calls, [validate_call(MCP_URL, &format!("Bearer {BARE}"))]);
    assert_answered(&response, StatusCode::UNAUTHORIZED, "unauthorized", "");
    assert_eq!(response.headers()["www-authenticate"], "Bearer");
}

#[test]
fn missing_permission_is_forbidden() {
    for permissions in [
        &["can_approve_invoice"][..],
        &["can_approve_invoice", "can_delete_reports"],
    ] {
        let case = format!("{permissions:?}");
        let (response, calls) = mcp(permissions, with_bearer(TOKEN));

        assert_eq!(
            calls,
            [validate_call(MCP_URL, &format!("Bearer {TOKEN}"))],
            "{case}"
        );
        assert_answered(&response, StatusCode::FORBIDDEN, "forbidden", &case);
    }
}

#[test]
fn any_required_permission_held_is_enough() {
    for permissions in [
        &["can_read_reports"][..],
        &["can_approve_invoice", "can_read_reports"],
    ] {
        let (response, _) = mcp(permissions, with_bearer(TOKEN));

        assert_attached(&response, &format!("{permissions:?}"));
    }
}

#[test]
fn validate_error_is_unavailable() {
    for token in [REFUSED, THROTTLED, REJECTED, GARBLED] {
        let (response, calls) = mcp(&[], with_bearer(token));

        assert_eq!(
            calls,
            [validate_call(MCP_URL, &format!("Bearer {token}"))],
            "{token}"
        );
        assert_answered(
            &response,
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            token,
        );
    }
}

#[test]
fn failing_validate_is_retried_then_unavailable() {
    let (response, calls) = mcp(&[], with_bearer(UNAVAILABLE));

    let call = || validate_call(MCP_URL, &format!("Bearer {UNAVAILABLE}"));
    assert_eq!(calls, [call(), call()]);
    assert_answered(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "",
    );
}

#[test]
fn https_is_reflected_in_the_mcp_url() {
    for (request, url) in [
        (
            mcp_request().header("x-forwarded-proto", "https"),
            "https://app.example.com/mcp",
        ),
        (
            mcp_request().header("x-forwarded-proto", "http"),
            "http://app.example.com/mcp",
        ),
        (
            Request::post("https://app.example.com/mcp"),
            "https://app.example.com/mcp",
        ),
        (
            Request::post("http://app.example.com:8080/mcp"),
            "http://app.example.com:8080/mcp",
        ),
    ] {
        let case = format!("{request:?}");
        let (response, calls) = mcp(
            &[],
            request.header("authorization", format!("Bearer {TOKEN}")),
        );

        assert_eq!(
            calls,
            [validate_call(url, &format!("Bearer {TOKEN}"))],
            "{case}"
        );
        assert_attached(&response, &case);
    }
}

#[test]
fn mcp_url_has_the_path_and_not_the_query_string() {
    for (uri, url) in [
        ("/mcp?session=abc&x=1", "http://app.example.com/mcp"),
        ("/api/v1/mcp/?x=1", "http://app.example.com/api/v1/mcp/"),
        (
            "/mcp/a&b=c%20d+e?mcp=http://evil.example/mcp",
            "http://app.example.com/mcp/a&b=c%20d+e",
        ),
    ] {
        let (response, calls) = mcp(
            &[],
            Request::post(uri)
                .header("host", "app.example.com")
                .header("authorization", format!("Bearer {TOKEN}")),
        );

        assert_eq!(
            calls,
            [validate_call(url, &format!("Bearer {TOKEN}"))],
            "{uri}"
        );
        assert_attached(&response, uri);
    }
}

#[test]
fn nested_mount_reports_the_public_path() {
    let _serial = serial();
    let platform = platform();
    recorded().clear();

    let mut app = Router::new().nest(
        "/api",
        Router::new().fallback(tool).layer(stackure::mcp(&[])),
    );
    let request = Request::post("/api/mcp")
        .header("host", "app.example.com")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let task = platform
        .runtime
        .spawn(async move { app.call(request).await.unwrap().status() });
    platform.runtime.block_on(task).unwrap();

    assert_eq!(
        std::mem::take(&mut *recorded()),
        [validate_call(
            "http://app.example.com/api/mcp",
            &format!("Bearer {TOKEN}")
        )]
    );
}
