//! Input validation utilities for the Stackure SDK.

use regex::Regex;
use std::sync::LazyLock;

use crate::errors::StackureError;

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap());

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        .unwrap()
});

/// Validate that a string is a well-formed email address.
///
/// # Errors
///
/// Returns [`StackureError::Validation`] if the email is empty or malformed.
pub fn validate_email(email: &str) -> Result<(), StackureError> {
    if email.is_empty() {
        return Err(StackureError::Validation(
            "Email is required and must be a string".into(),
        ));
    }
    if !EMAIL_RE.is_match(email) {
        return Err(StackureError::Validation("Invalid email format".into()));
    }
    Ok(())
}

/// Validate that a string is a valid UUID v4.
///
/// # Errors
///
/// Returns [`StackureError::Validation`] if the value is empty or not a valid UUID v4.
pub fn validate_uuid(value: &str, field_name: &str) -> Result<(), StackureError> {
    if value.is_empty() {
        return Err(StackureError::Validation(format!(
            "{field_name} is required and must be a string"
        )));
    }
    if !UUID_RE.is_match(value) {
        return Err(StackureError::Validation(format!(
            "Invalid {field_name} format (must be a valid UUID)"
        )));
    }
    Ok(())
}
