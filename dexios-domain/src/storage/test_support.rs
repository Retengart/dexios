//! Deterministic failure-injection seam for storage safety tests.
//!
//! This module is part of `dexios-domain`'s public surface **only** under the
//! `test-support` feature (or `cfg(test)`); see `storage::mod`, where the
//! declaration is source-gated to `pub mod` under that feature and a private
//! `mod` otherwise. Production builds therefore wall the seam off entirely: the
//! `pub` items below are deliberately unreachable from outside the crate.
//! Runtime workflows construct only `FailureHooks::none`, so the seam is inert
//! in production; the failure-driving entry points (`fail_on`, `check`, `point`)
//! exist for the `test-support`-gated integration tests that exercise the
//! commit/rollback paths.
#![cfg_attr(
    not(any(test, feature = "test-support")),
    expect(
        unreachable_pub,
        reason = "the failure-injection seam is public API only under `test-support` (or \
            `cfg(test)`); production builds declare `mod test_support` privately (source-gated \
            in `storage::mod`), so these `pub` items are intentionally unreachable — exactly \
            the cfg-conditional isolation `unreachable_pub` reports here"
    )
)]

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePoint {
    Write,
    Flush,
    Sync,
    Persist,
    PostCommitSync,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureError {
    point: FailurePoint,
}

impl FailureError {
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn point(&self) -> FailurePoint {
        self.point
    }
}

impl fmt::Display for FailureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "injected storage failure at {:?}", self.point)
    }
}

impl std::error::Error for FailureError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FailureHooks {
    fail_on: Option<FailurePoint>,
}

impl FailureHooks {
    #[must_use]
    pub fn none() -> Self {
        Self { fail_on: None }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn fail_on(point: FailurePoint) -> Self {
        Self {
            fail_on: Some(point),
        }
    }

    pub fn check(self, point: FailurePoint) -> Result<(), FailureError> {
        if self.fail_on == Some(point) {
            Err(FailureError { point })
        } else {
            Ok(())
        }
    }
}
