//! Stackure SDK error type.

use std::fmt;

/// The single error type returned by every fallible SDK function.
///
/// Match on the variant to branch on category, or call
/// [`StackureError::code`] for the stable string the other Stackure SDKs
/// expose as `.code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackureError {
    /// Input validation failed before a request was made.
    Validation(String),
    /// The API returned 401 Unauthorized.
    Auth(String),
    /// The API returned 403 Forbidden.
    Forbidden(String),
    /// The request exceeded the 2-second timeout.
    Timeout(String),
    /// Any other transport or API failure.
    Network(String),
}

impl StackureError {
    /// The stable, lowercase category: `"validation"`, `"auth"`,
    /// `"forbidden"`, `"timeout"`, or `"network"`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation",
            Self::Auth(_) => "auth",
            Self::Forbidden(_) => "forbidden",
            Self::Timeout(_) => "timeout",
            Self::Network(_) => "network",
        }
    }

    /// The human-readable description, without the `stackure:` prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Validation(m)
            | Self::Auth(m)
            | Self::Forbidden(m)
            | Self::Timeout(m)
            | Self::Network(m) => m,
        }
    }
}

impl fmt::Display for StackureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stackure: {}: {}", self.code(), self.message())
    }
}

impl std::error::Error for StackureError {}
