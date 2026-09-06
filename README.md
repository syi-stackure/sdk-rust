# Stackure Rust SDK

[![Check build](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml)
[![crates.io](https://img.shields.io/crates/v/stackure.svg)](https://crates.io/crates/stackure)
[![docs.rs](https://img.shields.io/docsrs/stackure)](https://docs.rs/stackure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Passwordless magic-link authentication SDK for Rust — drop-in tower middleware for axum, tonic, and hyper.

Protect an app with one line, or verify sessions and send magic links directly against the [Stackure](https://stackure.com) auth API.

## Install

```toml
[dependencies]
stackure = "1"
```

Requires Rust 2024 edition.

## Protect an app

```rust
use stackure::{auth, user_from_request};

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"; // your app's UUID in Stackure

let app = Router::new()
    .route("/admin", get(handler))
    .layer(auth(APP_ID, &["view_any_app"]));
```

Access the authenticated user in your handler:

```rust
let user = user_from_request(&parts).unwrap();
println!("{} {:?}", user.user_email, user.user_permissions);
```

In axum you can also take an `Extension<User>` directly.

- API requests get JSON errors
- Browser requests get redirected to sign-in
- The sign-in handoff is automatic: Stackure hands the browser back with a `session_token`, the layer stores it as a cookie on your domain and strips it from the URL

## Requirements

Stackure binds sessions to the browser's user agent and IP. The SDK validates
from your server, so it forwards the original `User-Agent` and
`X-Forwarded-For`. Your app must see the real client IP — if it runs behind a
proxy or CDN, make sure that layer sets `X-Forwarded-For`.

Without that header the SDK falls back to the peer address, read from axum's
`ConnectInfo<SocketAddr>`. Serve with `into_make_service_with_connect_info` to
make it available, or disable the default `axum` feature if you do not need it.

Every request is validated against Stackure, so revocation is immediate.

## Verify manually

```rust
let result = stackure::verify(APP_ID, &parts, &["view_any_app"]).await;

if !result.authenticated {
    let error = result.error.unwrap();
    // error.code, error.message, error.sign_in_url
}

// result.user
```

`verify` never returns an error — transport and API failures come back as a
500 result.

## Send a magic link

```rust
let response = stackure::send_magic_link("user@example.com", Some(APP_ID)).await?;
// response.message
```

## Log out

```rust
let response: Response<Body> = stackure::logout(&parts);
```

Returns a 303 that clears the app's cookie and redirects to Stackure's
sign-out.

## Configuration

Set `STACKURE_BASE_URL` to point at a non-production environment:

```bash
STACKURE_BASE_URL=https://stage.stackure.com cargo run
```

Retry-on-5xx (one retry after 500ms) and the 2-second request timeout are
hard-coded. Timeouts are never retried.

## Errors

Everything except `verify` returns `StackureError`. Match on the variant, or
call `.code()` for the same category string the other Stackure SDKs expose as
`.code`:

```rust
use stackure::StackureError;

match stackure::send_magic_link(email, None).await {
    Err(StackureError::Validation(m)) => {}  // bad input
    Err(StackureError::Auth(m)) => {}        // 401 from the API
    Err(StackureError::Forbidden(m)) => {}   // 403 from the API
    Err(StackureError::Timeout(m)) => {}     // exceeded the 2s timeout
    Err(StackureError::Network(m)) => {}     // everything else
    Ok(response) => {}
}
```

## Dependencies

Rust's standard library has no HTTP client and no TLS, so unlike the Go, JavaScript,
and Python SDKs this one cannot be dependency-free. It builds directly on `hyper`
and `rustls` — the stack axum and tonic already run on — rather than on a
higher-level client, so in a typical axum app it adds around twenty crates.

## Contributing

Open a PR. Releases are cut from `main` by release-plz.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-rust/security/advisories/new). Releases publish to crates.io via OIDC trusted publishing with [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
