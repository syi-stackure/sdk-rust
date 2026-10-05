//! `logout` when nothing is listening at the Stackure API address.

use axum::http::{Request, Response, StatusCode};
use tokio::runtime::Runtime;

#[test]
fn refused_connection_redirects_to_sign_out_page() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let base = format!("http://{closed}");
    // SAFETY: this is the only test in the binary and the runtime's threads
    // do not exist yet, so nothing else is reading the environment.
    unsafe {
        std::env::set_var("STACKURE_BASE_URL", &base);
    }

    let (parts, ()) = Request::post("/logout")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", "session=0b9f6c1e-5a3d-4c2b-9e8f-7a6b5c4d3e2f")
        .body(())
        .unwrap()
        .into_parts();
    let runtime = Runtime::new().unwrap();
    let task = runtime.spawn(async move { stackure::logout(&parts).await });
    let response: Response<()> = runtime.block_on(task).unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], format!("{base}/signout"));
    assert_eq!(
        response.headers()["set-cookie"],
        "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}
