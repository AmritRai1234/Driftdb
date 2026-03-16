//! DriftDB — Write-Ahead Log (WAL) with Encryption
//!
//! Every transaction writes its operations to the WAL BEFORE
//! modifying the main database. If DriftDB crashes, the WAL
//! is replayed on startup to recover committed transactions.
//!
//! Security: WAL records are encrypted with AES-256-GCM when
//! an encryption key is provided. This prevents attackers with
//! disk access from reading transaction data from the WAL file.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{DriftError, DriftResult};
use crate::transaction::{TxId, TxOp};

/// A single WAL record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    pub tx_id: TxId,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub entry: WalEntry,
    pub checksum: u32,
}

/// WAL entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    /// Transaction started
    Begin,
    /// A single operation
    Operation(TxOp),
    /// Transaction committed — all ops before this are durable
    Commit,
    /// Transaction aborted — ignore all previous ops
    Abort,
    /// Checkpoint — WAL can be truncated up to here
    Checkpoint { last_tx: TxId },
}

/// Write-Ahead Log implementation with optional encryption
pub struct Wal {
    path: PathBuf,
    sequence: u64,
    /// Optional AES-256-GCM encryption key for WAL records
    encryption_key: Option<[u8; 32]>,
}

impl Wal {
    /// Open or create a WAL at the given directory
    pub fn open<P: AsRef<Path>>(dir: P) -> DriftResult<Self> {
        let path = dir.as_ref().join("drift.wal");

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| DriftError::Storage(format!("Cannot create WAL directory: {}", e)))?;
        }

        // Restrict WAL file permissions on Unix
        #[cfg(unix)]
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }

        // Count existing records to set sequence
        let sequence = if path.exists() {
            let file = File::open(&path)
                .map_err(|e| DriftError::Storage(format!("Cannot open WAL: {}", e)))?;
            BufReader::new(file).lines().count() as u64
        } else {
            0
        };

        Ok(Wal {
            path,
            sequence,
            encryption_key: None,
        })
    }

    /// Enable encryption on the WAL with an AES-256 key
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Create an in-memory WAL for testing
    pub fn temporary() -> DriftResult<Self> {
        let dir = std::env::temp_dir().join(format!("driftdb_wal_{}", uuid::Uuid::new_v4()));
        Self::open(dir)
    }

    /// Write a record to the WAL (fsync'd to disk)
    pub fn write(&mut self, tx_id: TxId, entry: WalEntry) -> DriftResult<()> {
        self.sequence += 1;

        let record = WalRecord {
            tx_id,
            sequence: self.sequence,
            timestamp: Utc::now(),
            entry,
            checksum: 0, // Will be computed
        };

        let json = serde_json::to_string(&record)?;
        let checksum = crc32_of(json.as_bytes());

        // Encrypt if key is set, otherwise write plaintext (with checksum)
        let line = if let Some(ref key) = self.encryption_key {
            let encrypted = encrypt_wal_record(json.as_bytes(), key)?;
            let encoded = base64_encode(&encrypted);
            format!("E|{}|{}\n", checksum, encoded)
        } else {
            format!("{}|{}\n", checksum, json)
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| DriftError::Storage(format!("WAL write failed: {}", e)))?;

        file.write_all(line.as_bytes())
            .map_err(|e| DriftError::Storage(format!("WAL write failed: {}", e)))?;

        // fsync for durability
        file.sync_all()
            .map_err(|e| DriftError::Storage(format!("WAL fsync failed: {}", e)))?;

        // Restrict file permissions after creation
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.path, perms);
        }

        Ok(())
    }

    /// Log a complete transaction (begin + ops + commit/abort)
    pub fn log_transaction(&mut self, tx_id: TxId, ops: &[TxOp], committed: bool) -> DriftResult<()> {
        self.write(tx_id, WalEntry::Begin)?;

        for op in ops {
            self.write(tx_id, WalEntry::Operation(op.clone()))?;
        }

        if committed {
            self.write(tx_id, WalEntry::Commit)?;
        } else {
            self.write(tx_id, WalEntry::Abort)?;
        }

        Ok(())
    }

    /// Read all records from the WAL (for crash recovery)
    pub fn read_all(&self) -> DriftResult<Vec<WalRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)
            .map_err(|e| DriftError::Storage(format!("Cannot read WAL: {}", e)))?;

        let mut records = Vec::new();
        let mut corrupted = 0u64;

        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| DriftError::Storage(format!("WAL read error: {}", e)))?;

            // Check if this is an encrypted record (starts with "E|")
            if let Some(rest) = line.strip_prefix("E|") {
                // Encrypted record: E|checksum|base64_ciphertext
                if let Some((checksum_str, encoded)) = rest.split_once('|') {
                    if let Some(ref key) = self.encryption_key {
                        match base64_decode(encoded) {
                            Ok(encrypted) => match decrypt_wal_record(&encrypted, key) {
                                Ok(plaintext) => {
                                    let expected: u32 = checksum_str.parse().unwrap_or(0);
                                    let actual = crc32_of(&plaintext);
                                    if expected != actual {
                                        corrupted += 1;
                                        continue;
                                    }
                                    match serde_json::from_slice::<WalRecord>(&plaintext) {
                                        Ok(record) => records.push(record),
                                        Err(_) => corrupted += 1,
                                    }
                                }
                                Err(_) => corrupted += 1,
                            },
                            Err(_) => corrupted += 1,
                        }
                    } else {
                        // No key — can't decrypt, skip
                        corrupted += 1;
                    }
                }
            } else if let Some((checksum_str, json)) = line.split_once('|') {
                // Plaintext record: checksum|json
                let expected: u32 = checksum_str.parse().unwrap_or(0);
                let actual = crc32_of(json.as_bytes());

                if expected != actual {
                    corrupted += 1;
                    continue;
                }

                match serde_json::from_str::<WalRecord>(json) {
                    Ok(record) => records.push(record),
                    Err(_) => corrupted += 1,
                }
            }
        }

        if corrupted > 0 {
            eprintln!(
                "⚠ WAL recovery: {} corrupted records skipped",
                corrupted
            );
        }

        Ok(records)
    }

    /// Get transactions that were committed but may not have been applied
    pub fn get_committed_transactions(&self) -> DriftResult<Vec<(TxId, Vec<TxOp>)>> {
        let records = self.read_all()?;
        let mut tx_ops: std::collections::HashMap<u64, Vec<TxOp>> = std::collections::HashMap::new();
        let mut committed: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut aborted: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for record in &records {
            match &record.entry {
                WalEntry::Begin => {
                    tx_ops.entry(record.tx_id.0).or_default();
                }
                WalEntry::Operation(op) => {
                    tx_ops.entry(record.tx_id.0).or_default().push(op.clone());
                }
                WalEntry::Commit => {
                    committed.insert(record.tx_id.0);
                }
                WalEntry::Abort => {
                    aborted.insert(record.tx_id.0);
                }
                WalEntry::Checkpoint { .. } => {}
            }
        }

        let result: Vec<(TxId, Vec<TxOp>)> = committed
            .into_iter()
            .filter(|id| !aborted.contains(id))
            .filter_map(|id| {
                tx_ops.remove(&id).map(|ops| (TxId(id), ops))
            })
            .collect();

        Ok(result)
    }

    /// Write a checkpoint marker and truncate the WAL
    pub fn checkpoint(&mut self, last_tx: TxId) -> DriftResult<()> {
        self.write(last_tx, WalEntry::Checkpoint { last_tx })?;

        // Truncate the WAL file (since all data is safely in the main DB)
        File::create(&self.path)
            .map_err(|e| DriftError::Storage(format!("WAL truncation failed: {}", e)))?;

        self.sequence = 0;
        Ok(())
    }

    /// Get WAL file size in bytes
    pub fn size(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// Get record count
    pub fn record_count(&self) -> DriftResult<usize> {
        Ok(self.read_all()?.len())
    }

    /// Check if encryption is enabled
    pub fn is_encrypted(&self) -> bool {
        self.encryption_key.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════════
// WAL Encryption — AES-256-GCM
// ═══════════════════════════════════════════════════════════════════

/// Encrypt WAL data using AES-256-GCM (nonce || ciphertext)
fn encrypt_wal_record(plaintext: &[u8], key: &[u8; 32]) -> DriftResult<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Key, Nonce};
    use rand::RngCore;

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| DriftError::Internal(format!("WAL encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt WAL data (expects nonce || ciphertext)
fn decrypt_wal_record(data: &[u8], key: &[u8; 32]) -> DriftResult<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};

    if data.len() < 12 {
        return Err(DriftError::Internal("WAL record too short to decrypt".into()));
    }

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| DriftError::Internal(format!(
            "WAL decryption failed (data may be tampered): {}", e
        )))
}

// ═══════════════════════════════════════════════════════════════════
// Base64 encoding (no external deps — minimal inline impl)
// ═══════════════════════════════════════════════════════════════════

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(input: &str) -> DriftResult<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let decode_char = |c: u8| -> DriftResult<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(DriftError::Internal(format!("Invalid base64 char: {}", c as char))),
        }
    };

    let bytes = input.as_bytes();
    let chunks = bytes.chunks(4);
    for chunk in chunks {
        let mut val: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            val |= decode_char(byte)? << (18 - i * 6);
        }
        result.push((val >> 16) as u8);
        if chunk.len() > 2 {
            result.push((val >> 8) as u8);
        }
        if chunk.len() > 3 {
            result.push(val as u8);
        }
    }
    Ok(result)
}

/// Simple CRC32 checksum
fn crc32_of(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_write_read() {
        let mut wal = Wal::temporary().unwrap();
        let tx_id = TxId(1);

        wal.write(tx_id, WalEntry::Begin).unwrap();
        wal.write(tx_id, WalEntry::Operation(TxOp::InsertNode {
            node_id: "n_1".into(),
            data: vec![1, 2, 3],
        })).unwrap();
        wal.write(tx_id, WalEntry::Commit).unwrap();

        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_wal_committed_transactions() {
        let mut wal = Wal::temporary().unwrap();

        // TX 1: committed
        wal.log_transaction(TxId(1), &[
            TxOp::InsertNode { node_id: "n_1".into(), data: vec![] },
        ], true).unwrap();

        // TX 2: aborted
        wal.log_transaction(TxId(2), &[
            TxOp::InsertNode { node_id: "n_2".into(), data: vec![] },
        ], false).unwrap();

        let committed = wal.get_committed_transactions().unwrap();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].0, TxId(1));
    }

    #[test]
    fn test_wal_corruption_detection() {
        let mut wal = Wal::temporary().unwrap();
        wal.write(TxId(1), WalEntry::Begin).unwrap();

        // Corrupt the WAL file
        let mut file = OpenOptions::new()
            .append(true)
            .open(&wal.path)
            .unwrap();
        file.write_all(b"CORRUPTED|{garbage}\n").unwrap();

        // Valid records should still be recovered
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 1); // Only the valid one
    }

    #[test]
    fn test_wal_checkpoint() {
        let mut wal = Wal::temporary().unwrap();
        wal.write(TxId(1), WalEntry::Begin).unwrap();
        wal.write(TxId(1), WalEntry::Commit).unwrap();

        wal.checkpoint(TxId(1)).unwrap();
        assert_eq!(wal.size(), 0); // WAL should be empty after checkpoint
    }

    #[test]
    fn test_wal_encrypted_write_read() {
        let key = crate::security::Encryptor::generate_key();
        let mut wal = Wal::temporary().unwrap().with_encryption(key);

        wal.write(TxId(1), WalEntry::Begin).unwrap();
        wal.write(TxId(1), WalEntry::Operation(TxOp::InsertNode {
            node_id: "secret_node".into(),
            data: vec![42, 69, 255],
        })).unwrap();
        wal.write(TxId(1), WalEntry::Commit).unwrap();

        // Verify the file contains encrypted data (starts with "E|")
        let raw = std::fs::read_to_string(&wal.path).unwrap();
        assert!(raw.starts_with("E|"));
        // The raw file must NOT contain the plaintext node ID
        assert!(!raw.contains("secret_node"));

        // But reading with the key recovers the data
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_wal_encrypted_tamper_detection() {
        let key = crate::security::Encryptor::generate_key();
        let mut wal = Wal::temporary().unwrap().with_encryption(key);

        wal.write(TxId(1), WalEntry::Begin).unwrap();

        // Tamper with the encrypted WAL file
        let mut content = std::fs::read_to_string(&wal.path).unwrap();
        // Flip a character in the base64 ciphertext
        unsafe {
            let bytes = content.as_bytes_mut();
            if bytes.len() > 20 {
                bytes[20] ^= 0x01;
            }
        }
        std::fs::write(&wal.path, content).unwrap();

        // Reading should skip the corrupted record
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_wal_wrong_key_fails() {
        let key1 = crate::security::Encryptor::generate_key();
        let key2 = crate::security::Encryptor::generate_key();
        let mut wal = Wal::temporary().unwrap().with_encryption(key1);

        wal.write(TxId(1), WalEntry::Begin).unwrap();

        // Try to read with a different key
        let wal_path = wal.path.clone();
        let wal2 = Wal {
            path: wal_path,
            sequence: 0,
            encryption_key: Some(key2),
        };

        let records = wal2.read_all().unwrap();
        assert_eq!(records.len(), 0); // Can't decrypt with wrong key
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = vec![0u8, 1, 2, 255, 254, 128, 64, 32, 16, 8, 4, 2, 1];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
}
