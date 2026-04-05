//! Official Stackure authentication SDK for Rust.
//!
//! Provides session validation, magic-link authentication, and role-based
//! access control for Rust applications. Framework-agnostic.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn example() {
//! let result = stackure::verify("my-app-id", Some("session=abc"), Some(&["admin"])).await;
//! if result.authenticated {
//!     println!("{:?}", result.user);
//! }
//! # }
//! ```

pub mod client;
pub mod errors;
pub mod types;
pub mod validation;

mod verify_impl;

pub use client::{Client, Config};
pub use errors::StackureError;
pub use types::{MagicLinkResponse, SessionValidationResponse, User, VerifyError, VerifyResult};
pub use verify_impl::verify;
