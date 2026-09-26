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

## Configure

```bash
export STACKURE_APP_SECRET=...   # from the app page in Stackure, shown once
```

Sent as `X-App-Secret` on every call. The first call that actually reaches Stackure fails with `StackureError::Validation` when it is unset. `STACKURE_BASE_URL` optionally overrides the API host.

A newly registered app is not usable by anyone, even its creator, until it is shared with the organization or assigned to a team in Stackure. Do that before testing sign-in.

## Protect an app

```rust
use stackure::{auth, user_from_request};

const APP_ID: &str = "7f3c1a2e-9b4d-4e6f-8a1b-2c3d4e5f6071"; // your app's UUID in Stackure

let app = Router::new()
    .route("/admin", get(handler))
    .layer(auth(APP_ID, &["can_approve_invoice"]));
```

Access the authenticated user in your handler:

```rust
let user = user_from_request(&parts).unwrap();
println!("{} {:?}", user.user_email, user.user_permissions);
```

In axum you can also take an `Extension<User>` directly.

- API requests get JSON errors
- Browser requests get redirected to sign-in
- The sign-in handoff is automatic: Stackure POSTs a `session_token` (an app-scoped session token valid only for this app) back to your app, the layer validates it and stores it as a cookie on your domain. Handoff bodies over 4 KB are ignored

## Requirements

Sessions are not bound to the browser's user agent or IP. The SDK still
forwards the original `User-Agent` and `X-Forwarded-For` when validating from
your server, but they are informational only.

When `X-Forwarded-For` is absent the SDK falls back to the peer address, read
from axum's `ConnectInfo<SocketAddr>`. Serve with
`into_make_service_with_connect_info` to make it available, or disable the
default `axum` feature if you do not need it.

The app cookie is marked `Secure` only when the request arrived over TLS as far as the SDK can tell: send `X-Forwarded-Proto: https` from your TLS terminator, since a direct TLS listener is not visible from the request itself.

Every request with a session token is validated against Stackure, so revocation
is immediate. Requests without a well-formed token get the sign-in URL without a
Stackure call.

Every call has one 2-second wall-clock deadline covering connect, headers, body
and the single retry. The SDK retries once, after 500 ms, on a 5xx response or a
connection failure, and only if more than 500 ms of the deadline remain. A
timeout, including while reading the body, is `StackureError::Timeout` and is
never retried.

## Verify manually

```rust
let result = stackure::verify(APP_ID, &parts, &["can_approve_invoice"]).await;

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
    Err(StackureError::Timeout(m)) => {}     // exceeded the 2s deadline
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

Open a PR.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-rust/security/advisories/new). Releases publish to crates.io via OIDC trusted publishing with [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
