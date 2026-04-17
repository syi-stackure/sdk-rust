# Stackure Rust SDK

[![CI](https://github.com/syi-stackure/sdk-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/syi-stackure/sdk-rust/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/stackure.svg)](https://crates.io/crates/stackure)
[![docs.rs](https://img.shields.io/docsrs/stackure)](https://docs.rs/stackure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Authentication for your app. Framework-agnostic.

## Install

```toml
[dependencies]
stackure = "1"
```

## Verify a request

```rust
use stackure::verify;

let result = verify("my-app-id", Some("session=abc"), Some(&["admin"])).await;

if result.authenticated {
    let user = result.user.unwrap();
    println!("{} {:?}", user.user_email, user.user_roles);
} else {
    let err = result.error.unwrap();
    // err.code, err.message, err.sign_in_url
}
```

## Send a magic link

```rust
use stackure::send_magic_link;

send_magic_link("user@example.com", Some("my-app-id")).await?;
```

## Log out

```rust
use stackure::logout;

logout(Some("session=abc")).await?;
```

## Configuration

Set `STACKURE_BASE_URL` to point at a non-production environment:

```bash
STACKURE_BASE_URL=https://stage.stackure.com cargo run
```

## Errors

Every fallible function returns `StackureError`. Match on the variant, or use `.code()` for the stable string form matching the other Stackure SDKs:

```rust
use stackure::StackureError;

match send_magic_link(email, None).await {
    Ok(_) => {}
    Err(StackureError::Validation(msg)) => {}
    Err(StackureError::Auth(msg)) => {}
    Err(StackureError::Forbidden(msg)) => {}
    Err(StackureError::Timeout(msg)) => {}
    Err(StackureError::Network(msg)) => {}
}
```

## Contributing

Open a PR. Tag a release when ready: `git tag vX.Y.Z && git push --tags` — the release workflow builds, signs, and publishes.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/syi-stackure/sdk-rust/security/advisories/new). Releases are signed with [cosign](https://www.sigstore.dev/) and carry [GitHub build-provenance attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).

## License

MIT
