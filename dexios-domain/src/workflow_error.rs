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
    UnsupportedWorkflow,
    IncorrectKey,
    Other,
}

impl WorkflowErrorClass {
    pub const ALL: [Self; 11] = [
        Self::MalformedFormat,
        Self::UnsupportedFormat,
        Self::KdfFailure,
        Self::AuthenticationFailure,
        Self::UnsafePath,
        Self::IoFailure,
        Self::OverwriteDenied,
        Self::TransactionCommitFailure,
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
        IdentityError::Io(_) => WorkflowErrorClass::IoFailure,
    }
}

pub(crate) fn classify_transaction_error(error: &TransactionError) -> WorkflowErrorClass {
    match error {
        TransactionError::Write { .. }
        | TransactionError::Flush { .. }
        | TransactionError::Sync { .. } => WorkflowErrorClass::IoFailure,
        TransactionError::Persist { .. } | TransactionError::PartialCommit { .. } => {
            WorkflowErrorClass::TransactionCommitFailure
        }
    }
}
