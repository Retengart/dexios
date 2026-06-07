use std::error::Error as StdError;
use std::fmt;

use crate::workflow_error::WorkflowErrorClass;

#[derive(Debug)]
pub struct ArchiveFileCallbackError {
    class: WorkflowErrorClass,
    message: String,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl ArchiveFileCallbackError {
    pub fn other(message: impl Into<String>) -> Self {
        Self {
            class: WorkflowErrorClass::Other,
            message: message.into(),
            source: None,
        }
    }

    pub fn other_with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::other_with_boxed_source(message, Box::new(source))
    }

    pub fn other_with_boxed_source(
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync + 'static>,
    ) -> Self {
        Self {
            class: WorkflowErrorClass::Other,
            message: message.into(),
            source: Some(source),
        }
    }

    pub fn with_class(class: WorkflowErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_class_and_source<E>(
        class: WorkflowErrorClass,
        message: impl Into<String>,
        source: E,
    ) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            class,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn workflow_class(&self) -> WorkflowErrorClass {
        self.class
    }
}

impl fmt::Display for ArchiveFileCallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for ArchiveFileCallbackError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
