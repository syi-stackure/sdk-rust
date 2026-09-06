//! Input validation for the Stackure SDK.

use crate::errors::StackureError;

/// Validate that `email` is a well-formed address.
///
/// # Errors
///
/// Returns [`StackureError::Validation`] if empty or malformed.
pub fn validate_email(email: &str) -> Result<(), StackureError> {
    if email.is_empty() {
        return Err(StackureError::Validation("email is required".into()));
    }

    let bad = |s: &str| s.is_empty() || s.chars().any(|c| c.is_whitespace() || c == '@');
    let Some((local, domain)) = email.split_once('@') else {
        return Err(StackureError::Validation("invalid email format".into()));
    };
    let dotted = matches!(domain.find('.'), Some(i) if i > 0 && i + 1 < domain.len());

    if bad(local) || bad(domain) || !dotted {
        return Err(StackureError::Validation("invalid email format".into()));
    }
    Ok(())
}

/// Validate that `value` is a UUID v4.
///
/// # Errors
///
/// Returns [`StackureError::Validation`] if empty or not a valid UUID v4.
pub fn validate_uuid(value: &str, field_name: &str) -> Result<(), StackureError> {
    if value.is_empty() {
        return Err(StackureError::Validation(format!(
            "{field_name} is required"
        )));
    }

    let b = value.as_bytes();
    let shaped = b.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b[14] == b'4'
        && matches!(b[19] | 0x20, b'8' | b'9' | b'a' | b'b')
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit());

    if !shaped {
        return Err(StackureError::Validation(format!(
            "invalid {field_name} format (must be a valid UUID)"
        )));
    }
    Ok(())
}
