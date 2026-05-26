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

    pub fn check(&self, point: FailurePoint) -> Result<(), FailureError> {
        if self.fail_on == Some(point) {
            Err(FailureError { point })
        } else {
            Ok(())
        }
    }
}
