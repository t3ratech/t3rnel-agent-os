//! Kernel-specific error types.

use t3rnel_types::error::T3rnelError;
use thiserror::Error;

/// Kernel error type wrapping T3rnelError with kernel-specific context.
#[derive(Error, Debug)]
pub enum KernelError {
    /// A wrapped T3rnelError.
    #[error(transparent)]
    T3rnel(#[from] T3rnelError),

    /// The kernel failed to boot.
    #[error("Boot failed: {0}")]
    BootFailed(String),
}

/// Alias for kernel results.
pub type KernelResult<T> = Result<T, KernelError>;
