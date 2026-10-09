//! Identity facts and `directory` against a local stand-in for the Stackure API.

use std::future::Future;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use axum::body::Body;
use axum::extract::Query;
use axum::http::request::{Builder, Parts};
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::{Json, Router};
use stackure::{Directory, DirectoryUser, StackureError, Team, User};
use tokio::runtime::Runtime;
use tower::Service;

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
const APP_SECRET: &str = "app-secret-under-test";
const TOKEN: &str = "0b9f6c1e-5a3d-4c2b-9e8f-7a6b5c4d3e2f";
const INVALID: &str = "1c8e7d2f-6b4a-4d3c-8f9e-6b5a4c3d2e1f";
const REFUSED: &str = "2d7f8e3a-7c5b-4e4d-a0af-5c4b3d2e1f0a";
const THROTTLED: &str = "3e8a9f4b-8d6c-4f5e-b1b0-4d3c2e1f0a9b";
const REJECTED: &str = "4f9b0a5c-9e7d-4a6f-82c1-3e2d1f0a9b8c";
const ADMIN: &str = "5a0c1b6d-0f8e-4b7a-93d2-2f1e0a9b8c7d";
const MEMBER: &str = "6b1d2c7e-1a9f-4c8b-a4e3-1a0f9b8c7d6e";
const OLDER: &str = "7c2e3d8f-2b0a-4d9c-b5f4-0b1a2c3d4e5f";

#[derive(Debug, PartialEq)]
struct Call {
    path: String,
    query: Vec<(String, String)>,
    authorization: String,
    app_secret: String,
    cookie: String,
    user_agent: String,
    forwarded_for: String,
}

fn ada() -> User {
    User {
        user_id: "8d3f4e9a-3c1b-4eab-86a5-1c2b3d4e5f6a".into(),
        account_id: "9e4a5f0b-4d2c-4fbc-97b6-2d3c4e5f6a7b".into(),
        user_email: "ada@example.com".into(),
        user_first_name: "Ada".into(),
        user_last_name: "Lovelace".into(),
        user_is_app_admin: false,
        user_teams: Vec::new(),
    }
}

fn ops() -> Team {
    Team {
        team_id: "4b5c6d7e-8f9a-4b1c-8d2e-3f4a5b6c7d8e".into(),
        team_name: "Ops".into(),
    }
}

fn listed() -> Directory {
    Directory {
        users: vec![DirectoryUser {
            user_id: "8d3f4e9a-3c1b-4eab-86a5-1c2b3d4e5f6a".into(),
            user_email: "ada@example.com".into(),
            user_first_name: "Ada".into(),
            user_last_name: "Lovelace".into(),
        }],
        teams: vec![ops()],
    }
}

static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

fn recorded() -> MutexGuard<'static, Vec<Call>> {
    CALLS.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn api(
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
        path: uri.path().into(),
        query,
        authorization,
        app_secret: header("x-app-secret"),
        cookie,
        user_agent: header("user-agent"),
        forwarded_for: header("x-forwarded-for"),
    });
    let mut user = serde_json::json!({
        "user_id": "8d3f4e9a-3c1b-4eab-86a5-1c2b3d4e5f6a",
        "account_id": "9e4a5f0b-4d2c-4fbc-97b6-2d3c4e5f6a7b",
        "user_email": "ada@example.com",
        "user_first_name": "Ada",
        "user_last_name": "Lovelace",
    });
    match token.as_str() {
        TOKEN => return Json(listed()).into_response(),
        INVALID => {
            return (StatusCode::UNAUTHORIZED, r#"{"error":"invalid session"}"#).into_response();
        }
        REFUSED => {
            return (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid app secret"}"#,
            )
                .into_response();
        }
        THROTTLED => {
            return (StatusCode::TOO_MANY_REQUESTS, r#"{"error":"rate limited"}"#).into_response();
        }
        REJECTED => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid app_id format"}"#,
            )
                .into_response();
        }
        ADMIN => {
            user["user_is_app_admin"] = true.into();
            user["user_teams"] = serde_json::json!([ops()]);
        }
        MEMBER => {
            user["user_is_app_admin"] = false.into();
            user["user_teams"] = serde_json::json!([]);
        }
        _ => {}
    }
    Json(serde_json::json!({ "authenticated": true, "user": user })).into_response()
}

struct Platform {
    runtime: Runtime,
}

fn platform() -> &'static Platform {
    static PLATFORM: OnceLock<Platform> = OnceLock::new();
    PLATFORM.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        // SAFETY: every test holds `serial` by the time it gets here, and the
        // runtime's threads do not exist yet, so nothing else is reading the
        // environment.
        unsafe {
            std::env::set_var(
                "STACKURE_BASE_URL",
                format!("http://{}", listener.local_addr().unwrap()),
            );
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
        Platform { runtime }
    })
}

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn run<F: Future>(future: impl FnOnce() -> F) -> (F::Output, Vec<Call>) {
    let _serial = serial();
    let platform = platform();
    recorded().clear();
    let out = platform.runtime.block_on(future());
    (out, std::mem::take(&mut *recorded()))
}

fn browser() -> Builder {
    Request::get("/share")
        .header("user-agent", "browser/1")
        .header("x-forwarded-for", "203.0.113.7")
}

fn parts(request: Builder) -> Parts {
    request.body(()).unwrap().into_parts().0
}

fn with_session(token: &str) -> Parts {
    parts(browser().header("cookie", format!("session={token}")))
}

fn directory_call(token: &str) -> Call {
    Call {
        path: "/api/public/directory".into(),
        query: vec![("app_id".into(), APP_ID.into())],
        authorization: String::new(),
        app_secret: APP_SECRET.into(),
        cookie: format!("session={token}"),
        user_agent: "browser/1".into(),
        forwarded_for: "203.0.113.7".into(),
    }
}

async fn tool(parts: Parts) -> Json<Option<User>> {
    Json(stackure::user_from_request(&parts).cloned())
}

#[test]
fn identity_facts_are_decoded_for_session_and_mcp_users() {
    let admin = User {
        user_is_app_admin: true,
        user_teams: vec![ops()],
        ..ada()
    };
    for (token, want) in [(ADMIN, admin), (MEMBER, ada()), (OLDER, ada())] {
        let session = with_session(token);
        let (result, _) = run(|| stackure::validate_session(&session));
        assert_eq!(result.unwrap().user, Some(want.clone()), "{token}");

        let request = Request::post("/mcp")
            .header("host", "app.example.com")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let mut app = Router::new().fallback(tool).layer(stackure::mcp());
        let (body, _) = run(|| async move {
            let response = app.call(request).await.unwrap();
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
        });
        assert_eq!(
            serde_json::from_slice::<Option<User>>(&body).unwrap(),
            Some(want),
            "{token}"
        );
    }
}

#[test]
fn directory_lists_users_and_teams() {
    let session = with_session(TOKEN);
    let (result, calls) = run(|| stackure::directory(&session));

    assert_eq!(result, Ok(listed()));
    assert_eq!(calls, [directory_call(TOKEN)]);
}

#[test]
fn directory_errors_map_like_other_api_errors() {
    for (token, want) in [
        (
            INVALID,
            StackureError::Auth(r#"{"error":"invalid session"}"#.into()),
        ),
        (
            REFUSED,
            StackureError::Auth(r#"{"error":"invalid app secret"}"#.into()),
        ),
        (
            THROTTLED,
            StackureError::Network(r#"api error (429): {"error":"rate limited"}"#.into()),
        ),
        (
            REJECTED,
            StackureError::Network(r#"api error (400): {"error":"invalid app_id format"}"#.into()),
        ),
    ] {
        let session = with_session(token);
        let (result, calls) = run(|| stackure::directory(&session));

        assert_eq!(result, Err(want), "{token}");
        assert_eq!(calls, [directory_call(token)], "{token}");
    }
}

#[test]
fn directory_without_a_session_is_auth_without_a_call() {
    for request in [
        browser(),
        browser().header("cookie", "session=not-a-token"),
        browser().header("authorization", format!("Bearer {TOKEN}")),
    ] {
        let case = format!("{request:?}");
        let request = parts(request);
        let (result, calls) = run(|| stackure::directory(&request));

        assert_eq!(
            result,
            Err(StackureError::Auth("invalid session".into())),
            "{case}"
        );
        assert!(calls.is_empty(), "{case}");
    }
}
