//! Secure memory handling for sensitive data
//!
//! This module provides a `Protected` wrapper that ensures sensitive data
//! is securely erased from memory when dropped and is hidden from debug output.
//!
//! The implementation is inspired by the [secrecy crate](https://crates.io/crates/secrecy)
//! and provides similar functionality for protecting sensitive information.

use std::fmt::Debug;
use zeroize::Zeroize;

/// A wrapper for sensitive data that provides secure memory handling
///
/// `Protected` ensures that:
/// - Data is automatically zeroized when dropped
/// - Data is hidden from debug output (shows `[REDACTED]`)
/// - Data can only be accessed explicitly via `expose()`
/// - Data cannot be accidentally copied (only cloned explicitly)
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::Protected;
///
/// let password = "my-secret-password".to_string();
/// let protected_password = Protected::new(password);
///
/// // Access the data explicitly
/// let password_ref = protected_password.expose();
/// 
/// // Data is automatically zeroized when dropped
/// drop(protected_password);
/// ```
#[derive(Clone)]
pub struct Protected<T>
where
    T: Zeroize,
{
    data: T,
}

impl<T> std::ops::Deref for Protected<T>
where
    T: Zeroize,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> Protected<T>
where
    T: Zeroize,
{
    /// Creates a new `Protected` wrapper around the provided value
    ///
    /// # Arguments
    ///
    /// * `value` - The sensitive data to protect
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Protected;
    ///
    /// let secret = Protected::new("sensitive data".to_string());
    /// ```
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { data: value }
    }

    /// Exposes the protected data for use
    ///
    /// This is the only way to access the data within a `Protected` wrapper.
    /// The explicit nature of this method makes it easy to audit where
    /// sensitive data is being accessed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Protected;
    ///
    /// let secret = Protected::new("password".to_string());
    /// let password_ref = secret.expose();
    /// ```
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.data
    }

    /// Consumes the `Protected` wrapper and returns the inner value
    ///
    /// This method transfers ownership of the inner value to the caller.
    /// Use with caution as the caller becomes responsible for secure handling.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Protected;
    ///
    /// let secret = Protected::new("password".to_string());
    /// let password = secret.into_inner();
    /// ```
    #[must_use]
    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T> Drop for Protected<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<T> Debug for Protected<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Creates a `Protected` wrapper around a byte vector
///
/// This is a convenience function for creating protected byte vectors
/// which are commonly used for passwords and keys.
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::protected_bytes;
///
/// let password = protected_bytes(b"my-password");
/// ```
#[must_use]
pub fn protected_bytes(data: &[u8]) -> Protected<Vec<u8>> {
    Protected::new(data.to_vec())
}

/// Creates a `Protected` wrapper around a string
///
/// This is a convenience function for creating protected strings
/// which are commonly used for passwords.
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::protected_string;
///
/// let password = protected_string("my-password");
/// ```
#[must_use]
pub fn protected_string(data: &str) -> Protected<String> {
    Protected::new(data.to_string())
}