use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn server(mode: &'static str, hits: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
            }
            if mode == "hang" {
                std::thread::sleep(std::time::Duration::from_secs(6));
                continue;
            }
            let fail = mode == "500" || (mode == "flaky" && n == 1);
            let resp = if fail {
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nboom".to_string()
            } else {
                let b = r#"{"message":"ok"}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                )
            };
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}")
}

async fn run(mode: &'static str) -> (String, String, usize, u128) {
    let hits = Arc::new(AtomicUsize::new(0));
    let base = server(mode, hits.clone());
    unsafe { std::env::set_var("STACKURE_BASE_URL", base) };
    let start = Instant::now();
    let out = match stackure::send_magic_link("a@b.co", None).await {
        Ok(r) => ("ok".to_string(), r.message),
        Err(e) => (e.code().to_string(), e.message().to_string()),
    };
    (
        out.0,
        out.1,
        hits.load(Ordering::SeqCst),
        start.elapsed().as_millis(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn transport_matches_other_sdks() {
    for (mode, code, want_hits) in [
        ("hang", "timeout", 1),
        ("500", "network", 2),
        ("flaky", "ok", 2),
    ] {
        let (got, msg, hits, ms) = run(mode).await;
        println!("{mode:<6} -> {got:<8} {msg:<32} hits={hits} {ms}ms");
        assert_eq!((got.as_str(), hits), (code, want_hits), "mode {mode}");
        match mode {
            "hang" => assert!((1900..2600).contains(&ms), "timeout took {ms}ms"),
            "500" => assert!((450..1200).contains(&ms), "retry delay was {ms}ms"),
            _ => {}
        }
    }
}
