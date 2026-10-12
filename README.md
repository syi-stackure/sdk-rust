# Stackure Rust SDK

[![Check build](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml)
[![crates.io](https://img.shields.io/crates/v/stackure.svg)](https://crates.io/crates/stackure)
[![docs.rs](https://img.shields.io/docsrs/stackure)](https://docs.rs/stackure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Add Stackure sign-in to axum, tonic and hyper with tower middleware.

## Install

```toml
[dependencies]
stackure = "1"
```

Needs Rust 1.85 or later.

## Example

Set `STACKURE_APP_ID` and `STACKURE_APP_SECRET` from the app's page in Stackure, then add the layer:

```rust
use axum::{Extension, Router, routing::get};
use stackure::User;

async fn admin(Extension(user): Extension<User>) -> String {
    user.user_email
}

let app = Router::new()
    .route("/admin", get(admin))
    .layer(stackure::auth());
```

## Documentation

Configuration, sign-in handoff, MCP, sign-out, errors and limits: [stackure.com/docs/rust](https://stackure.com/docs/rust)

## License

MIT
