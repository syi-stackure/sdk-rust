//! Stackure SDK error type.

/// The single error type returned by every SDK function.
///
/// Match on the variant to branch on category, or call
/// [`StackureError::code`] for a stable string matching the other SDKs.
#[derive(Debug, thiserror::Error)]
pub enum StackureError {
    /// Input validation failed before a request was made.
    #[error("stackure: validation: {0}")]
    Validation(String),

    /// An HTTP request failed or the API returned an unsuccessful response.
    #[error("stackure: network: {0}")]
    Network(String),

    /// The API returned a 401 Unauthorized response.
    #[error("stackure: auth: {0}")]
    Auth(String),

    /// An HTTP request exceeded the timeout.
    #[error("stackure: timeout: {0}")]
    Timeout(String),

    /// The authenticated user lacks the required role.
    #[error("stackure: forbidden: {0}")]
    Forbidden(String),
}

impl StackureError {
    /// Returns a stable, lowercase category string (`"validation"`, `"network"`,
    /// `"auth"`, `"timeout"`, or `"forbidden"`). Matches the `.code` field on
    /// the other Stackure SDKs.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation",
            Self::Network(_) => "network",
            Self::Auth(_) => "auth",
            Self::Timeout(_) => "timeout",
            Self::Forbidden(_) => "forbidden",
        }
    }
}
