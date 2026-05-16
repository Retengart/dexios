use crate::storage::Error as StorageError;
use crate::storage::cleanup::{CleanupFailure, CleanupResult};
use crate::storage::identity::IdentityError;
use crate::storage::transaction::TransactionError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WorkflowErrorClass {
    MalformedFormat,
    UnsupportedFormat,
    KdfFailure,
    AuthenticationFailure,
    UnsafePath,
    IoFailure,
    OverwriteDenied,
    TransactionCommitFailure,
    CleanupFailure,
    ResourcePressure,
    UnsupportedWorkflow,
    IncorrectKey,
    Other,
}

impl WorkflowErrorClass {
    pub const ALL: [Self; 13] = [
        Self::MalformedFormat,
        Self::UnsupportedFormat,
        Self::KdfFailure,
        Self::AuthenticationFailure,
        Self::UnsafePath,
        Self::IoFailure,
        Self::OverwriteDenied,
        Self::TransactionCommitFailure,
        Self::CleanupFailure,
        Self::ResourcePressure,
        Self::UnsupportedWorkflow,
        Self::IncorrectKey,
        Self::Other,
    ];
}

pub(crate) fn classify_identity_error(error: &IdentityError) -> WorkflowErrorClass {
    match error {
        IdentityError::AliasedPath { .. } | IdentityError::UnsafePath(_) => {
            WorkflowErrorClass::UnsafePath
        }
        IdentityError::Io(_) | IdentityError::IoWithSource { .. } => WorkflowErrorClass::IoFailure,
    }
}

pub(crate) fn classify_transaction_error(error: &TransactionError) -> WorkflowErrorClass {
    if matches!(error, TransactionError::PartialCommit { .. }) {
        return WorkflowErrorClass::TransactionCommitFailure;
    }

    if error.is_resource_pressure() {
        return WorkflowErrorClass::ResourcePressure;
    }

    match error {
        TransactionError::Write { .. }
        | TransactionError::Flush { .. }
        | TransactionError::Sync { .. } => WorkflowErrorClass::IoFailure,
        TransactionError::Persist { .. } | TransactionError::PartialCommit { .. } => {
            WorkflowErrorClass::TransactionCommitFailure
        }
    }
}

pub(crate) fn classify_storage_error(error: &StorageError) -> WorkflowErrorClass {
    if error.is_resource_pressure() {
        return WorkflowErrorClass::ResourcePressure;
    }

    match error {
        StorageError::UnsafePath(_) => WorkflowErrorClass::UnsafePath,
        StorageError::CreateDir
        | StorageError::CreateDirWithSource(_)
        | StorageError::CreateFile
        | StorageError::CreateFileWithSource(_)
        | StorageError::OpenFile(_)
        | StorageError::OpenFileWithSource { .. }
        | StorageError::RemoveFile
        | StorageError::RemoveFileWithSource(_)
        | StorageError::RemoveDir
        | StorageError::RemoveDirWithSource(_)
        | StorageError::DirEntries
        | StorageError::DirEntriesWithSource(_)
        | StorageError::FlushFile
        | StorageError::FlushFileWithSource(_)
        | StorageError::SyncFile
        | StorageError::SyncFileWithSource(_)
        | StorageError::FileAccess
        | StorageError::FileAccessWithSource(_)
        | StorageError::FileLen
        | StorageError::FileLenWithSource(_) => WorkflowErrorClass::IoFailure,
    }
}

#[must_use]
pub fn classify_cleanup_failure(_failure: &CleanupFailure) -> WorkflowErrorClass {
    WorkflowErrorClass::CleanupFailure
}

#[must_use]
pub fn classify_cleanup_result(result: &CleanupResult) -> WorkflowErrorClass {
    if result.failures.is_empty() {
        WorkflowErrorClass::Other
    } else {
        WorkflowErrorClass::CleanupFailure
    }
}
