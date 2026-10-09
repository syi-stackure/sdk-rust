//! `mcp` when nothing is listening at the Stackure API address.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::runtime::Runtime;
use tower::Service;

#[test]
fn refused_connection_is_unavailable() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // SAFETY: this is the only test in the binary and the runtime's threads
    // do not exist yet, so nothing else is reading the environment.
    unsafe {
        std::env::set_var("STACKURE_BASE_URL", format!("http://{closed}"));
        std::env::set_var("STACKURE_APP_ID", "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071");
        std::env::set_var("STACKURE_APP_SECRET", "app-secret-under-test");
    }

    let request = Request::post("/mcp")
        .header("host", "app.example.com")
        .header(
            "authorization",
            "Bearer 0b9f6c1e-5a3d-4c2b-9e8f-7a6b5c4d3e2f",
        )
        .body(Body::empty())
        .unwrap();
    let mut app = Router::new()
        .fallback(|| async { "reached the MCP route" })
        .layer(stackure::mcp());
    let runtime = Runtime::new().unwrap();
    let task = runtime.spawn(async move {
        let (parts, body) = app.call(request).await.unwrap().into_parts();
        (parts, axum::body::to_bytes(body, usize::MAX).await.unwrap())
    });
    let (parts, body) = runtime.block_on(task).unwrap();

    assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(parts.headers["content-type"], "application/json");
    assert_eq!(body, r#"{"error":"unavailable"}"#);
    assert!(!parts.headers.contains_key("www-authenticate"));
    assert!(!parts.headers.contains_key("set-cookie"));
}
