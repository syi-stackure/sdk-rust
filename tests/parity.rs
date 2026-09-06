use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use http::{Request, StatusCode};
use tower::ServiceExt;

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071";
const TOK: &str = "tok-abc123";

#[derive(Default, Clone, Debug)]
struct Seen {
    cookie: String,
    ua: String,
    xff: String,
}

fn fake_stackure(seen: &Arc<Mutex<Seen>>) -> String {
    let seen = seen.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(&stream, &seen);
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn serve(stream: &std::net::TcpStream, seen: &Arc<Mutex<Seen>>) {
    let mut out = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let magic_link = line.contains("magic-link");

    let mut s = Seen::default();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        let (k, v) = h.split_once(':').unwrap_or(("", ""));
        let v = v.trim().to_string();
        match k.to_ascii_lowercase().as_str() {
            "cookie" => s.cookie = v,
            "user-agent" => s.ua = v,
            "x-forwarded-for" => s.xff = v,
            "content-length" => len = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    if len > 0 {
        let _ = reader.read_exact(&mut vec![0u8; len]);
    }
    let authed = s.cookie == format!("session={TOK}");
    *seen.lock().unwrap() = s;

    let body = if magic_link {
        r#"{"message":"Magic link sent"}"#
    } else if authed {
        r#"{"authenticated":true,"user":{"user_id":"u1","user_email":"a@b.co","user_first_name":"A","user_last_name":"B","user_permissions":["can_approve_invoice"]}}"#
    } else {
        r#"{"authenticated":false,"sign_in_url":"https://stackure.test/sign-in"}"#
    };
    let len = body.len();
    let _ = out.write_all(
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}").as_bytes(),
    );
}

fn app(permissions: &'static [&'static str]) -> Router {
    Router::new()
        .route(
            "/admin",
            get(|req: Request<Body>| async move {
                let (parts, _) = req.into_parts();
                let user = stackure::user_from_request(&parts).unwrap();
                format!("hello {}", user.user_email)
            })
            .post(|body: String| async move { body }),
        )
        .layer(stackure::auth(APP_ID, permissions))
}

struct Res {
    status: StatusCode,
    location: String,
    set_cookie: String,
    body: String,
}

async fn call(app: Router, req: Request<Body>) -> Res {
    let res = app.oneshot(req).await.unwrap();
    let header = |n: &str| {
        res.headers()
            .get(n)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    };
    let (status, location, set_cookie) = (res.status(), header("location"), header("set-cookie"));
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    Res {
        status,
        location,
        set_cookie,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn req(method: &str, uri: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("user-agent", "TestUA")
        .header("x-forwarded-for", "203.0.113.9, 10.0.0.1")
}

fn show(label: &str, r: &Res) {
    println!(
        "{label:<24} {} loc={:?} sc={:?} {:?}",
        r.status.as_u16(),
        r.location,
        r.set_cookie,
        r.body
    );
}

async fn handoff(seen: &Arc<Mutex<Seen>>) {
    let form = req("POST", "/admin")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("session_token={TOK}")))
        .unwrap();
    let r = call(app(&["can_approve_invoice"]), form).await;
    show("POST form handoff", &r);
    assert_eq!(
        (r.status, r.location.as_str()),
        (StatusCode::SEE_OTHER, "/admin")
    );
    assert!(r.set_cookie.contains(&format!("session={TOK}")) && r.set_cookie.contains("HttpOnly"));

    let query = req("GET", &format!("/admin?a=1&session_token={TOK}"))
        .body(Body::empty())
        .unwrap();
    let r = call(app(&["can_approve_invoice"]), query).await;
    show("GET query handoff", &r);
    assert_eq!(
        (r.status, r.location.as_str()),
        (StatusCode::SEE_OTHER, "/admin?a=1")
    );

    let authed = req("GET", "/admin")
        .header("cookie", format!("session={TOK}; other=1"))
        .body(Body::empty())
        .unwrap();
    let r = call(app(&["can_approve_invoice"]), authed).await;
    show("authed", &r);
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, "hello a@b.co")
    );

    let s = seen.lock().unwrap().clone();
    println!("forwarded to stackure    {s:?}");
    assert_eq!(
        s.cookie,
        format!("session={TOK}"),
        "only the session cookie"
    );
    assert_eq!((s.ua.as_str(), s.xff.as_str()), ("TestUA", "203.0.113.9"));
}

async fn peer_addr_fallback(seen: &Arc<Mutex<Seen>>) {
    let mut no_xff = Request::builder()
        .method("GET")
        .uri("/admin")
        .header("user-agent", "TestUA")
        .header("cookie", format!("session={TOK}"))
        .body(Body::empty())
        .unwrap();
    no_xff.extensions_mut().insert(axum::extract::ConnectInfo(
        "198.51.100.7:44321"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
    ));

    let r = call(app(&["can_approve_invoice"]), no_xff).await;
    show("no XFF, ConnectInfo", &r);
    assert_eq!(r.status, StatusCode::OK);
    let s = seen.lock().unwrap().clone();
    println!("forwarded (peer addr)    {s:?}");
    assert_eq!(s.xff, "198.51.100.7", "peer address must reach Stackure");
}

async fn rejections() {
    let html = req("GET", "/admin")
        .header("accept", "text/html")
        .body(Body::empty())
        .unwrap();
    let r = call(app(&["can_approve_invoice"]), html).await;
    show("401 html", &r);
    assert_eq!(
        (r.status, r.location.as_str()),
        (StatusCode::FOUND, "https://stackure.test/sign-in")
    );

    let json = req("GET", "/admin")
        .header("accept", "application/json")
        .body(Body::empty())
        .unwrap();
    let r = call(app(&["can_approve_invoice"]), json).await;
    show("401 json", &r);
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains(r#""error":"Unauthorized""#));
    assert!(
        r.body
            .contains(r#""sign_in_url":"https://stackure.test/sign-in""#)
    );

    let forbidden = req("GET", "/admin")
        .header("cookie", format!("session={TOK}"))
        .body(Body::empty())
        .unwrap();
    let r = call(app(&["nope_perm"]), forbidden).await;
    show("403 perms", &r);
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.body.contains(r#""error":"Forbidden""#));
    assert!(r.body.contains("Requires one of: nope_perm"));
    assert!(r.body.contains(r#""sign_in_url":"""#));
}

async fn body_reaches_handler() {
    let passthrough = req("POST", "/admin")
        .header("cookie", format!("session={TOK}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("x=1&y=2"))
        .unwrap();
    let r = call(app(&[]), passthrough).await;
    show("body replay", &r);
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "x=1&y=2"));
}

fn logout_and_validation_checks(base: &str) {
    let parts = req("GET", "/logout")
        .body(Body::empty())
        .unwrap()
        .into_parts()
        .0;
    let out: http::Response<Body> = stackure::logout(&parts);
    println!(
        "logout                   {} loc={:?} sc={:?}",
        out.status().as_u16(),
        out.headers()["location"],
        out.headers()["set-cookie"]
    );
    assert_eq!(out.status(), StatusCode::SEE_OTHER);
    assert_eq!(out.headers()["location"], format!("{base}/signout"));
    let cookie = out.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("Max-Age=0") && cookie.starts_with("session=;"));
}

async fn magic_link_checks() {
    let m = stackure::send_magic_link("user@example.com", Some(APP_ID))
        .await
        .unwrap();
    println!("magic link               {m:?}");
    assert_eq!(m.message, "Magic link sent");

    for (input, want) in [
        ("not-an-email", "invalid email format"),
        ("", "email is required"),
    ] {
        let e = stackure::send_magic_link(input, None).await.unwrap_err();
        println!("bad email {input:<14} ({:?}, {:?})", e.code(), e.message());
        assert_eq!((e.code(), e.message()), ("validation", want));
    }

    let e = stackure::send_magic_link("a@b.co", Some("not-a-uuid"))
        .await
        .unwrap_err();
    println!(
        "bad appid                ({:?}, {:?})",
        e.code(),
        e.message()
    );
    assert_eq!(e.message(), "invalid App ID format (must be a valid UUID)");
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_with_other_sdks() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let base = fake_stackure(&seen);
    unsafe { std::env::set_var("STACKURE_BASE_URL", format!("{base}/")) };

    handoff(&seen).await;
    peer_addr_fallback(&seen).await;
    rejections().await;
    body_reaches_handler().await;
    logout_and_validation_checks(&base);
    magic_link_checks().await;
}
