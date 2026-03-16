//! DriftDB — ACID Transaction Engine
//!
//! Provides full ACID guarantees:
//! - **Atomicity**: All operations in a transaction succeed or all are rolled back
//! - **Consistency**: Data integrity constraints are enforced
//! - **Isolation**: Concurrent transactions don't interfere (serializable via RwLock)
//! - **Durability**: Committed data survives crashes (via WAL + sled flush)

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{DriftError, DriftResult};

// ═══════════════════════════════════════════════════════════════════
// Transaction ID
// ═══════════════════════════════════════════════════════════════════

static TX_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique transaction identifier
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxId(pub u64);

impl TxId {
    pub fn next() -> Self {
        TxId(TX_COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tx_{}", self.0)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transaction Operations (Write-Ahead Log entries)
// ═══════════════════════════════════════════════════════════════════

/// A single operation within a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxOp {
    InsertNode {
        node_id: String,
        data: Vec<u8>,
    },
    UpdateNode {
        node_id: String,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    DeleteNode {
        node_id: String,
        old_data: Vec<u8>,
    },
    InsertEdge {
        edge_id: String,
        data: Vec<u8>,
    },
    DeleteEdge {
        edge_id: String,
        old_data: Vec<u8>,
    },
    InsertIndex {
        key: Vec<u8>,
    },
    RemoveIndex {
        key: Vec<u8>,
    },
    AttachVector {
        node_id: String,
        data: Vec<u8>,
    },
}

/// Transaction state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxState {
    Active,
    Committed,
    RolledBack,
    Failed,
}

// ═══════════════════════════════════════════════════════════════════
// Transaction
// ═══════════════════════════════════════════════════════════════════

/// A transaction that groups multiple operations atomically
#[derive(Debug)]
pub struct Transaction {
    pub id: TxId,
    pub state: TxState,
    pub started_at: DateTime<Utc>,
    pub operations: Vec<TxOp>,
    pub savepoints: Vec<(String, usize)>, // (name, op_index)
}

impl Transaction {
    /// Begin a new transaction
    pub fn begin() -> Self {
        Transaction {
            id: TxId::next(),
            state: TxState::Active,
            started_at: Utc::now(),
            operations: Vec::new(),
            savepoints: Vec::new(),
        }
    }

    /// Add an operation to the transaction
    pub fn add_op(&mut self, op: TxOp) -> DriftResult<()> {
        if self.state != TxState::Active {
            return Err(DriftError::Internal(format!(
                "Transaction {} is not active (state: {:?})",
                self.id, self.state
            )));
        }
        self.operations.push(op);
        Ok(())
    }

    /// Create a savepoint (for partial rollback)
    pub fn savepoint(&mut self, name: &str) {
        self.savepoints.push((name.to_string(), self.operations.len()));
    }

    /// Rollback to a savepoint (removes operations after the savepoint)
    pub fn rollback_to_savepoint(&mut self, name: &str) -> DriftResult<()> {
        let idx = self.savepoints.iter().rposition(|(n, _)| n == name);
        match idx {
            Some(sp_idx) => {
                let (_, op_idx) = self.savepoints[sp_idx].clone();
                self.operations.truncate(op_idx);
                self.savepoints.truncate(sp_idx);
                Ok(())
            }
            None => Err(DriftError::Internal(format!(
                "Savepoint '{}' not found",
                name
            ))),
        }
    }

    /// Get operation count
    pub fn op_count(&self) -> usize {
        self.operations.len()
    }

    /// Mark as committed
    pub fn mark_committed(&mut self) {
        self.state = TxState::Committed;
    }

    /// Mark as rolled back
    pub fn mark_rolled_back(&mut self) {
        self.state = TxState::RolledBack;
    }

    /// Mark as failed
    pub fn mark_failed(&mut self) {
        self.state = TxState::Failed;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transaction Manager
// ═══════════════════════════════════════════════════════════════════

/// Manages active transactions and provides serializable isolation
pub struct TransactionManager {
    /// Global read-write lock for serializable isolation
    pub lock: Arc<RwLock<()>>,
    /// Active transaction count
    active_count: AtomicU64,
    /// Total committed
    committed_count: AtomicU64,
    /// Total rolled back
    rollback_count: AtomicU64,
}

impl TransactionManager {
    pub fn new() -> Self {
        TransactionManager {
            lock: Arc::new(RwLock::new(())),
            active_count: AtomicU64::new(0),
            committed_count: AtomicU64::new(0),
            rollback_count: AtomicU64::new(0),
        }
    }

    /// Begin a write transaction (exclusive lock)
    pub fn begin_write(&self) -> WriteGuard<'_> {
        let guard = self.lock.write();
        self.active_count.fetch_add(1, Ordering::Relaxed);
        WriteGuard {
            _guard: guard,
            tx: Transaction::begin(),
        }
    }

    /// Begin a read transaction (shared lock — multiple readers allowed)
    pub fn begin_read(&self) -> ReadGuard<'_> {
        let guard = self.lock.read();
        ReadGuard { _guard: guard }
    }

    /// Record a commit
    pub fn record_commit(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
        self.committed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rollback
    pub fn record_rollback(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
        self.rollback_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get stats
    pub fn stats(&self) -> TxStats {
        TxStats {
            active: self.active_count.load(Ordering::Relaxed),
            committed: self.committed_count.load(Ordering::Relaxed),
            rolled_back: self.rollback_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for a write transaction
pub struct WriteGuard<'a> {
    _guard: parking_lot::RwLockWriteGuard<'a, ()>,
    pub tx: Transaction,
}

/// RAII guard for a read transaction
pub struct ReadGuard<'a> {
    _guard: parking_lot::RwLockReadGuard<'a, ()>,
}

/// Transaction statistics
#[derive(Debug, Clone)]
pub struct TxStats {
    pub active: u64,
    pub committed: u64,
    pub rolled_back: u64,
}

impl std::fmt::Display for TxStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Active: {} | Committed: {} | Rolled back: {}",
            self.active, self.committed, self.rolled_back
        )
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_lifecycle() {
        let mut tx = Transaction::begin();
        assert_eq!(tx.state, TxState::Active);
        assert_eq!(tx.op_count(), 0);

        tx.add_op(TxOp::InsertNode {
            node_id: "n_001".into(),
            data: vec![1, 2, 3],
        }).unwrap();
        assert_eq!(tx.op_count(), 1);

        tx.mark_committed();
        assert_eq!(tx.state, TxState::Committed);

        // Can't add ops after commit
        assert!(tx.add_op(TxOp::InsertNode {
            node_id: "n_002".into(),
            data: vec![],
        }).is_err());
    }

    #[test]
    fn test_savepoints() {
        let mut tx = Transaction::begin();
        tx.add_op(TxOp::InsertNode { node_id: "n_1".into(), data: vec![] }).unwrap();
        tx.add_op(TxOp::InsertNode { node_id: "n_2".into(), data: vec![] }).unwrap();

        tx.savepoint("sp1");

        tx.add_op(TxOp::InsertNode { node_id: "n_3".into(), data: vec![] }).unwrap();
        tx.add_op(TxOp::InsertNode { node_id: "n_4".into(), data: vec![] }).unwrap();
        assert_eq!(tx.op_count(), 4);

        tx.rollback_to_savepoint("sp1").unwrap();
        assert_eq!(tx.op_count(), 2); // Only first 2 ops remain
    }

    #[test]
    fn test_transaction_ids_unique() {
        let tx1 = Transaction::begin();
        let tx2 = Transaction::begin();
        assert_ne!(tx1.id, tx2.id);
    }

    #[test]
    fn test_transaction_manager_concurrency() {
        let mgr = TransactionManager::new();

        // Multiple readers should be allowed simultaneously
        let _r1 = mgr.begin_read();
        let _r2 = mgr.begin_read();
        let _r3 = mgr.begin_read();
        // All three readers coexist — no deadlock
    }

    #[test]
    fn test_transaction_manager_stats() {
        let mgr = TransactionManager::new();

        {
            let _wg = mgr.begin_write();
            assert_eq!(mgr.stats().active, 1);
        }

        mgr.record_commit();
        let stats = mgr.stats();
        assert_eq!(stats.committed, 1);
    }
}
