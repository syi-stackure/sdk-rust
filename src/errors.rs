//! Stackure SDK error types.

/// The primary error type for all Stackure SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum StackureError {
    /// Input validation failed before a request was made.
    #[error("Validation error: {0}")]
    Validation(String),

    /// An HTTP request failed or the API returned an error response.
    #[error("Network error: {0}")]
    Network(String),

    /// The API returned a 401 Unauthorized response.
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// An HTTP request exceeded the configured timeout.
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// The authenticated user lacks the required role or permission.
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

// Convenience aliases matching the Python SDK's error hierarchy.

/// Alias for a validation error.
pub type ValidationError = StackureError;

/// Alias for a network error.
pub type NetworkError = StackureError;

/// Alias for an authentication error.
pub type AuthenticationError = StackureError;

/// Alias for a timeout error.
pub type TimeoutError = StackureError;

/// Alias for a forbidden error.
pub type ForbiddenError = StackureError;
