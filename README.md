# Stackure Rust SDK

Authentication for your app. Framework-agnostic.

## Install

```toml
stackure = "1"
```

## Verify a Request

```rust
use stackure::verify;

let result = verify("my-app-id", Some(cookies), Some(&["admin"])).await;

if result.authenticated {
    let user = result.user.unwrap();
    println!("{} {:?}", user.user_email, user.user_roles);
} else {
    let err = result.error.unwrap();
    // err.code, err.message, err.sign_in_url
}
```

## Client Functions

```rust
use stackure::Client;

let client = Client::with_defaults();

client.send_magic_link("user@example.com", Some("my-app-id")).await?;
client.sign_in("my-app-id", Some("user@example.com")).await?;

let session = client.validate_session("my-app-id", Some(cookies)).await?;
// session.authenticated, session.user, session.sign_in_url

client.logout(Some(cookies)).await?;
```

## Custom Client

```rust
use stackure::{Client, Config};
use std::time::Duration;

let client = Client::new(Config {
    base_url: "https://staging.stackure.com".into(),
    timeout: Duration::from_secs(5),
});
```

## Errors

`StackureError::Validation` | `Network` | `Authentication` | `Timeout` | `Forbidden`

## License

MIT
