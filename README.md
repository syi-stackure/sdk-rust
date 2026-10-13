# Stackure Rust SDK

[![Check build](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml/badge.svg)](https://github.com/syi-stackure/sdk-rust/actions/workflows/check-build.yml)
[![crates.io](https://img.shields.io/crates/v/stackure.svg)](https://crates.io/crates/stackure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

[Stackure](https://stackure.com) is passwordless auth for B2B apps. This SDK adds it to axum, tonic and hyper services as tower middleware.

## Install

```toml
[dependencies]
stackure = "1"
```

Needs Rust 1.85 or later.

## Quickstart

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

## Docs

- Guide and reference: [stackure.com/docs/rust](https://stackure.com/docs/rust)
- For AI agents: [stackure.com/llms.txt](https://stackure.com/llms.txt)

## License

MIT
