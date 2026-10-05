//! `logout` against a local stand-in for the Stackure API.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::request::Builder;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use http_body::Frame;
use tokio::runtime::Runtime;
use tokio::time::Sleep;

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
const APP_SECRET: &str = "app-secret-under-test";
const TOKEN: &str = "0b9f6c1e-5a3d-4c2b-9e8f-7a6b5c4d3e2f";
const REVOKED: &str = "1c8e7d2f-6b4a-4d3c-8f9e-6b5a4c3d2e1f";
const UNAVAILABLE: &str = "2d7f8e3a-7c5b-4e4d-a0af-5c4b3d2e1f0a";
const BODILESS: &str = "3e8a9f4b-8d6c-4f5e-b1b0-4d3c2e1f0a9b";
const MOVED: &str = "4f9b0a5c-9e7d-4a6f-82c1-3e2d1f0a9b8c";
const SILENT: &str = "5a0c1b6d-0f8e-4b7a-93d2-2f1e0a9b8c7d";
const SLOW: &str = "6b1d2c7e-1a9f-4c8b-a4e3-1a0f9b8c7d6e";
const CUT_SHORT: &str = "7c2e3d8f-2b0a-4d9c-b5f4-0b1a2c3d4e5f";

#[derive(Debug, PartialEq)]
struct Call {
    method: String,
    path: String,
    authorization: String,
    content_length: String,
    app_secret: bool,
    cookie: bool,
    body: usize,
}

fn sign_out_call(token: &str) -> Call {
    Call {
        method: "POST".into(),
        path: "/api/public/auth/sign-out".into(),
        authorization: format!("Bearer {token}"),
        content_length: "0".into(),
        app_secret: false,
        cookie: false,
        body: 0,
    }
}

/// A response body that breaks off partway: its first bytes go out, and once
/// they have had time to reach the caller the connection is aborted.
#[derive(Default)]
struct CutShort(Option<Pin<Box<Sleep>>>);

impl http_body::Body for CutShort {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let Some(sent) = self.0.as_mut() else {
            self.0 = Some(Box::pin(tokio::time::sleep(Duration::from_millis(50))));
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                br#"{"message":"signed"#,
            )))));
        };
        sent.as_mut()
            .poll(cx)
            .map(|()| Some(Err(std::io::ErrorKind::ConnectionAborted.into())))
    }
}

static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

fn recorded() -> MutexGuard<'static, Vec<Call>> {
    CALLS.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn api(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let authorization = header("authorization");
    let token = authorization
        .strip_prefix("Bearer ")
        .unwrap_or_default()
        .to_string();
    if token == SLOW {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    recorded().push(Call {
        method: method.to_string(),
        path: uri.to_string(),
        authorization,
        content_length: header("content-length"),
        app_secret: headers.contains_key("x-app-secret"),
        cookie: headers.contains_key("cookie"),
        body: body.len(),
    });
    match token.as_str() {
        TOKEN | SLOW => {
            (StatusCode::OK, r#"{"message":"signed out successfully"}"#).into_response()
        }
        BODILESS => StatusCode::OK.into_response(),
        CUT_SHORT => Body::new(CutShort::default()).into_response(),
        MOVED => (StatusCode::FOUND, [("location", "/")]).into_response(),
        UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        SILENT => std::future::pending().await,
        _ => (StatusCode::UNAUTHORIZED, r#"{"error":"Unauthorized"}"#).into_response(),
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

fn same_origin_post(cookie: &str) -> Builder {
    Request::post("/logout")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", cookie)
}

fn signed_in(request: Builder) -> Builder {
    request.header("cookie", format!("session={TOKEN}"))
}

fn logout(request: Builder) -> (Response<()>, Vec<Call>) {
    let _serial = serial();
    let platform = platform();
    recorded().clear();

    let (parts, ()) = request.body(()).unwrap().into_parts();
    let task = platform
        .runtime
        .spawn(async move { stackure::logout(&parts).await });
    let response = platform.runtime.block_on(task).unwrap();
    (response, std::mem::take(&mut *recorded()))
}

fn assert_cleared_and_sent_to(response: &Response<()>, path: &str) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        format!("{}{path}", platform().base)
    );
    assert_eq!(
        response.headers()["set-cookie"],
        "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

fn assert_untouched_and_sent_to_sign_out_page(request: Builder) {
    let case = format!("{request:?}");
    let (response, calls) = logout(request);

    assert_eq!(calls, [], "{case}");
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "{case}");
    assert_eq!(
        response.headers()["location"],
        format!("{}/signout", platform().base),
        "{case}"
    );
    assert!(!response.headers().contains_key("set-cookie"), "{case}");
}

#[test]
fn same_origin_post_signs_out_then_redirects_to_stackure() {
    let (response, calls) = logout(same_origin_post(&format!("theme=dark; session={TOKEN}")));

    assert_eq!(calls, [sign_out_call(TOKEN)]);
    assert_cleared_and_sent_to(&response, "/");
}

#[test]
fn no_token_makes_no_call() {
    let (response, calls) = logout(same_origin_post("theme=dark"));

    assert_eq!(calls, []);
    assert_cleared_and_sent_to(&response, "/");
}

#[test]
fn malformed_token_makes_no_call() {
    let (response, calls) = logout(same_origin_post("session=not-a-session-token"));

    assert_eq!(calls, []);
    assert_cleared_and_sent_to(&response, "/");
}

#[test]
fn empty_success_body_counts_as_signed_out() {
    let (response, calls) = logout(same_origin_post(&format!("session={BODILESS}")));

    assert_eq!(calls, [sign_out_call(BODILESS)]);
    assert_cleared_and_sent_to(&response, "/");
}

#[test]
fn cut_short_success_body_counts_as_signed_out_in_one_call() {
    let (response, calls) = logout(same_origin_post(&format!("session={CUT_SHORT}")));

    assert_eq!(calls, [sign_out_call(CUT_SHORT)]);
    assert_cleared_and_sent_to(&response, "/");
}

#[test]
fn rejected_call_redirects_to_sign_out_page() {
    let (response, calls) = logout(same_origin_post(&format!("session={REVOKED}")));

    assert_eq!(calls, [sign_out_call(REVOKED)]);
    assert_cleared_and_sent_to(&response, "/signout");
}

#[test]
fn failing_call_is_retried_then_redirects_to_sign_out_page() {
    let (response, calls) = logout(same_origin_post(&format!("session={UNAVAILABLE}")));

    assert_eq!(
        calls,
        [sign_out_call(UNAVAILABLE), sign_out_call(UNAVAILABLE)]
    );
    assert_cleared_and_sent_to(&response, "/signout");
}

#[test]
fn redirect_reply_is_not_followed_and_redirects_to_sign_out_page() {
    let (response, calls) = logout(same_origin_post(&format!("session={MOVED}")));

    assert_eq!(calls, [sign_out_call(MOVED)]);
    assert_cleared_and_sent_to(&response, "/signout");
}

#[test]
fn unanswered_call_times_out_then_redirects_to_sign_out_page() {
    let (response, calls) = logout(same_origin_post(&format!("session={SILENT}")));

    assert_eq!(calls, [sign_out_call(SILENT)]);
    assert_cleared_and_sent_to(&response, "/signout");
}

#[test]
fn sign_out_completes_after_the_browser_disconnects() {
    let _serial = serial();
    let platform = platform();
    recorded().clear();

    let (parts, ()) = same_origin_post(&format!("session={SLOW}"))
        .body(())
        .unwrap()
        .into_parts();
    let abandoned = platform.runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(50), stackure::logout::<()>(&parts))
            .await
            .is_err()
    });
    assert!(abandoned);

    let deadline = Instant::now() + Duration::from_secs(5);
    while recorded().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*recorded(), [sign_out_call(SLOW)]);
}

#[test]
fn post_with_matching_origin_signs_out() {
    for request in [
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com"),
        Request::post("/logout")
            .header("host", "app.example.com:8443")
            .header("origin", "https://App.Example.com:8443"),
        Request::post("http://app.example.com/logout").header("origin", "http://app.example.com"),
    ] {
        let case = format!("{request:?}");
        let (response, calls) = logout(signed_in(request));

        assert_eq!(calls, [sign_out_call(TOKEN)], "{case}");
        assert_cleared_and_sent_to(&response, "/");
    }
}

#[test]
fn https_post_with_https_origin_signs_out() {
    for request in [
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("x-forwarded-proto", "https")
            .header("origin", "https://app.example.com"),
        Request::post("https://app.example.com/logout").header("origin", "https://app.example.com"),
    ] {
        let case = format!("{request:?}");
        let (response, calls) = logout(signed_in(request));

        assert_eq!(calls, [sign_out_call(TOKEN)], "{case}");
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{case}");
        assert_eq!(
            response.headers()["location"],
            format!("{}/", platform().base),
            "{case}"
        );
        assert_eq!(
            response.headers()["set-cookie"],
            "session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0",
            "{case}"
        );
    }
}

#[test]
fn https_post_with_http_origin_is_sent_to_sign_out_page_untouched() {
    for request in [
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("x-forwarded-proto", "https")
            .header("origin", "http://app.example.com"),
        Request::post("https://app.example.com/logout").header("origin", "http://app.example.com"),
    ] {
        assert_untouched_and_sent_to_sign_out_page(signed_in(request));
    }
}

#[test]
fn empty_sec_fetch_site_with_matching_origin_is_sent_to_sign_out_page_untouched() {
    assert_untouched_and_sent_to_sign_out_page(signed_in(
        Request::post("/logout")
            .header("sec-fetch-site", "")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com"),
    ));
}

#[test]
fn repeated_header_is_sent_to_sign_out_page_untouched() {
    for request in [
        Request::post("/logout")
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-site", "same-origin"),
        Request::post("/logout")
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-site", "cross-site"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com")
            .header("origin", "https://app.example.com"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com")
            .header("origin", "https://evil.example"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("host", "evil.example")
            .header("origin", "https://app.example.com"),
        Request::post("/logout")
            .header("sec-fetch-site", "same-origin")
            .header("origin", "https://app.example.com")
            .header("origin", "https://app.example.com"),
        Request::post("/logout")
            .header("sec-fetch-site", "same-origin")
            .header("host", "app.example.com")
            .header("host", "app.example.com"),
    ] {
        assert_untouched_and_sent_to_sign_out_page(signed_in(request));
    }
}

#[test]
fn post_with_look_alike_origin_is_sent_to_sign_out_page_untouched() {
    for origin in [
        "https://app.example.com.evil.example",
        "https://app.example.community",
        "https://app.example.co",
        "https://app.example.com@evil.example",
        "https://evilapp.example.com",
        "https://evil.app.example.com",
        "https://pp.example.com",
        "https://evil.example/app.example.com",
    ] {
        assert_untouched_and_sent_to_sign_out_page(signed_in(
            Request::post("/logout")
                .header("host", "app.example.com")
                .header("origin", origin),
        ));
    }
}

#[test]
fn get_is_sent_to_sign_out_page_untouched() {
    assert_untouched_and_sent_to_sign_out_page(signed_in(
        Request::get("/logout").header("sec-fetch-site", "same-origin"),
    ));
}

#[test]
fn cross_site_post_is_sent_to_sign_out_page_untouched() {
    assert_untouched_and_sent_to_sign_out_page(signed_in(
        Request::post("/logout").header("sec-fetch-site", "cross-site"),
    ));
}

#[test]
fn post_with_other_origin_is_sent_to_sign_out_page_untouched() {
    assert_untouched_and_sent_to_sign_out_page(signed_in(
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://evil.example"),
    ));
}

#[test]
fn any_other_request_is_sent_to_sign_out_page_untouched() {
    for request in [
        Request::head("/logout").header("sec-fetch-site", "same-origin"),
        Request::post("/logout").header("sec-fetch-site", "same-site"),
        Request::post("/logout").header("sec-fetch-site", "none"),
        Request::post("/logout"),
        Request::post("/logout").header("host", "app.example.com"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "null"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com:8443"),
        Request::post("/logout")
            .header("host", "app.example.com")
            .header("origin", "https://app.example.com")
            .header("sec-fetch-site", "cross-site"),
    ] {
        assert_untouched_and_sent_to_sign_out_page(signed_in(request));
    }
}

#[test]
fn other_calls_send_the_configured_app_secret() {
    let _serial = serial();
    let platform = platform();
    recorded().clear();

    let (parts, ()) = signed_in(Request::get("/")).body(()).unwrap().into_parts();
    let task = platform
        .runtime
        .spawn(async move { stackure::validate_session(&parts).await });
    let _ = platform.runtime.block_on(task).unwrap();

    let calls = std::mem::take(&mut *recorded());
    assert_eq!(calls.len(), 1);
    assert!(calls[0].app_secret && calls[0].cookie);
}
