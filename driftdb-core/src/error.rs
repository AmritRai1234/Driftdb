//! DriftDB Core — Error types

use thiserror::Error;

/// All errors that can occur within DriftDB
#[derive(Error, Debug)]
pub enum DriftError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Edge not found: {0}")]
    EdgeNotFound(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("Vector dimension mismatch: expected {expected}, got {got}")]
    DimensionMismatch { expected: usize, got: usize },

    #[error("Index out of bounds: {0}")]
    IndexOutOfBounds(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sled::Error> for DriftError {
    fn from(e: sled::Error) -> Self {
        DriftError::Storage(e.to_string())
    }
}

impl From<bincode::Error> for DriftError {
    fn from(e: bincode::Error) -> Self {
        DriftError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for DriftError {
    fn from(e: serde_json::Error) -> Self {
        DriftError::Serialization(e.to_string())
    }
}

pub type DriftResult<T> = Result<T, DriftError>;
