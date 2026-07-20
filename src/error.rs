//! The crate's single error type.

/// Errors from building, loading, or verifying DIG peer mTLS material.
#[derive(Debug, thiserror::Error)]
pub enum DigTlsError {
    /// The embedded or supplied CA PEM could not be parsed.
    #[error("DigNetwork CA material is invalid: {0}")]
    Ca(String),

    /// Building or signing a per-peer node certificate failed.
    #[error("node certificate generation failed: {0}")]
    CertGen(String),

    /// A stored certificate or key PEM could not be parsed back.
    #[error("certificate material could not be parsed: {0}")]
    Parse(String),

    /// A rustls configuration could not be assembled from the material.
    #[error("rustls configuration failed: {0}")]
    RustlsConfig(String),

    /// Reading or writing persisted certificate material failed.
    #[error("certificate persistence I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The crate result alias.
pub type Result<T> = std::result::Result<T, DigTlsError>;
