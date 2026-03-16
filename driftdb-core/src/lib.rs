//! # DriftDB Core
//!
//! The foundational crate for DriftDB — a next-generation database.
//!
//! Provides:
//! - **Types** — Rich value types, node/edge identifiers, temporal metadata
//! - **Storage** — Sled-backed persistent storage with temporal versioning
//! - **Temporal** — Time-travel queries, version history, soft-deletion
//! - **Events** — Every mutation emits typed events for subscription
//! - **Security** — AES-256 encryption, Argon2 auth, integrity checks, audit logging
//! - **Transactions** — Full ACID with savepoints and serializable isolation
//! - **WAL** — Write-ahead log for crash recovery with CRC32 checksums
//! - **Compression** — LZ4 compression with smart thresholds
//! - **Ops** — Backup/restore, health diagnostics, configuration

pub mod compression;
pub mod error;
pub mod event;
pub mod heap;
pub mod ops;
pub mod security;
pub mod storage;
pub mod sync;
pub mod temporal;
pub mod transaction;
pub mod types;
pub mod wal;

pub use error::{DriftError, DriftResult};
pub use event::{DriftEvent, EventBus};
pub use storage::Storage;
pub use types::*;

