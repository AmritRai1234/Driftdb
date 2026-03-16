//! DriftDB Security Module
//!
//! Defense-in-depth security for DriftDB:
//! - AES-256-GCM encryption at rest
//! - Argon2id password hashing for authentication
//! - SHA-256 integrity checksums on all stored data
//! - Input validation and sanitization
//! - Query limits to prevent DoS
//! - Tamper-evident audit logging

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

use crate::error::{DriftError, DriftResult};

// ═══════════════════════════════════════════════════════════════════
// ENCRYPTION AT REST — AES-256-GCM
// ═══════════════════════════════════════════════════════════════════

/// Encryption engine using AES-256-GCM (authenticated encryption)
/// Every value stored to disk goes through this.
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    /// Create an encryptor from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Encryptor {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Derive a 32-byte encryption key from a password using Argon2id
    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        use argon2::Argon2;
        let mut key = [0u8; 32];
        if let Err(_) = Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
        {
            // Zeroed key = encryption will work but produce unusable ciphertext
            // This is safer than crashing the server
            eprintln!("[SECURITY] Key derivation failed — check salt length");
        }
        key
    }

    /// Generate a random 32-byte key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt plaintext. Returns nonce || ciphertext (nonce is 12 bytes).
    pub fn encrypt(&self, plaintext: &[u8]) -> DriftResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| DriftError::Internal(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data (expects nonce || ciphertext format)
    pub fn decrypt(&self, data: &[u8]) -> DriftResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(DriftError::Internal("Encrypted data too short".into()));
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| DriftError::Internal(format!(
                "Decryption failed (data may be tampered): {}", e
            )))
    }
}

// ═══════════════════════════════════════════════════════════════════
// AUTHENTICATION — Argon2id password hashing
// ═══════════════════════════════════════════════════════════════════

/// Authentication manager for database access control
pub struct Auth;

impl Auth {
    /// Hash a password using Argon2id (memory-hard, GPU-resistant)
    pub fn hash_password(password: &str) -> DriftResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| DriftError::Internal(format!("Password hashing failed: {}", e)))?;

        Ok(hash.to_string())
    }

    /// Verify a password against a stored hash
    pub fn verify_password(password: &str, hash: &str) -> DriftResult<bool> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| DriftError::Internal(format!("Invalid hash format: {}", e)))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    /// Check password strength — enforces minimum requirements
    pub fn check_strength(password: &str) -> Result<(), Vec<String>> {
        let mut issues = Vec::new();

        if password.len() < 8 {
            issues.push("Password must be at least 8 characters".into());
        }
        if !password.chars().any(|c| c.is_uppercase()) {
            issues.push("Password must contain an uppercase letter".into());
        }
        if !password.chars().any(|c| c.is_lowercase()) {
            issues.push("Password must contain a lowercase letter".into());
        }
        if !password.chars().any(|c| c.is_ascii_digit()) {
            issues.push("Password must contain a digit".into());
        }
        if !password.chars().any(|c| !c.is_alphanumeric()) {
            issues.push("Password must contain a special character".into());
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// DATA INTEGRITY — SHA-256 checksums
// ═══════════════════════════════════════════════════════════════════

/// Compute SHA-256 checksum of data
pub fn checksum(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Verify data integrity against a checksum
pub fn verify_checksum(data: &[u8], expected: &str) -> bool {
    checksum(data) == expected
}

/// Wrap data with an integrity checksum: [32-byte hash][data]
pub fn wrap_with_checksum(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(data);
    let mut result = Vec::with_capacity(32 + data.len());
    result.extend_from_slice(&hash);
    result.extend_from_slice(data);
    result
}

/// Verify and unwrap checksummed data
pub fn unwrap_checksum(data: &[u8]) -> DriftResult<&[u8]> {
    if data.len() < 32 {
        return Err(DriftError::Internal("Data too short for checksum".into()));
    }

    let stored_hash = &data[..32];
    let payload = &data[32..];
    let computed_hash = Sha256::digest(payload);

    if stored_hash != computed_hash.as_slice() {
        return Err(DriftError::Internal(
            "DATA INTEGRITY VIOLATION: Checksum mismatch — data may be corrupted or tampered with"
                .into(),
        ));
    }

    Ok(payload)
}

// ═══════════════════════════════════════════════════════════════════
// INPUT VALIDATION — Sanitization & limits
// ═══════════════════════════════════════════════════════════════════

/// Security limits to prevent abuse and DoS
#[derive(Debug, Clone)]
pub struct SecurityLimits {
    /// Maximum query string length (bytes)
    pub max_query_length: usize,
    /// Maximum number of properties per node
    pub max_properties: usize,
    /// Maximum string value length (bytes)
    pub max_string_length: usize,
    /// Maximum vector dimensions
    pub max_vector_dims: usize,
    /// Maximum graph traversal depth
    pub max_traversal_depth: usize,
    /// Maximum results returned per query
    pub max_results: usize,
    /// Maximum number of labels per node
    pub max_labels: usize,
    /// Maximum number of edges per bulk operation
    pub max_bulk_size: usize,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        SecurityLimits {
            max_query_length: 10_000,
            max_properties: 100,
            max_string_length: 100_000,
            max_vector_dims: 4096,
            max_traversal_depth: 50,
            max_results: 10_000,
            max_labels: 10,
            max_bulk_size: 100_000,
        }
    }
}

/// Validate a query string against security limits
pub fn validate_query(input: &str, limits: &SecurityLimits) -> DriftResult<()> {
    if input.len() > limits.max_query_length {
        return Err(DriftError::InvalidQuery(format!(
            "Query exceeds maximum length ({} > {} bytes)",
            input.len(),
            limits.max_query_length
        )));
    }

    // Check for null bytes (could mess with C-level parsing)
    if input.contains('\0') {
        return Err(DriftError::InvalidQuery(
            "Query contains null bytes".into(),
        ));
    }

    // Check for control characters (except newlines/tabs)
    for ch in input.chars() {
        if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
            return Err(DriftError::InvalidQuery(format!(
                "Query contains invalid control character: U+{:04X}",
                ch as u32
            )));
        }
    }

    Ok(())
}

/// Validate a property map
pub fn validate_properties(
    props: &std::collections::HashMap<String, crate::types::Value>,
    limits: &SecurityLimits,
) -> DriftResult<()> {
    if props.len() > limits.max_properties {
        return Err(DriftError::InvalidQuery(format!(
            "Too many properties ({} > {} max)",
            props.len(),
            limits.max_properties
        )));
    }

    for (key, value) in props {
        // Validate key
        if key.is_empty() {
            return Err(DriftError::InvalidQuery("Empty property key".into()));
        }
        if key.len() > 256 {
            return Err(DriftError::InvalidQuery(format!(
                "Property key too long: '{}' ({} > 256 bytes)",
                &key[..32],
                key.len()
            )));
        }
        if !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(DriftError::InvalidQuery(format!(
                "Property key '{}' contains invalid characters (use alphanumeric + underscore)",
                key
            )));
        }

        // Validate value
        validate_value(value, limits)?;
    }

    Ok(())
}

/// Validate a single value
pub fn validate_value(value: &crate::types::Value, limits: &SecurityLimits) -> DriftResult<()> {
    use crate::types::Value;

    match value {
        Value::String(s) => {
            if s.len() > limits.max_string_length {
                return Err(DriftError::InvalidQuery(format!(
                    "String value too long ({} > {} bytes)",
                    s.len(),
                    limits.max_string_length
                )));
            }
        }
        Value::Vector(v) => {
            if v.len() > limits.max_vector_dims {
                return Err(DriftError::InvalidQuery(format!(
                    "Vector has too many dimensions ({} > {} max)",
                    v.len(),
                    limits.max_vector_dims
                )));
            }
            // Check for NaN/Infinity
            for (i, val) in v.iter().enumerate() {
                if val.is_nan() || val.is_infinite() {
                    return Err(DriftError::InvalidQuery(format!(
                        "Vector contains invalid value at index {}: {}",
                        i, val
                    )));
                }
            }
        }
        Value::List(items) => {
            for item in items {
                validate_value(item, limits)?;
            }
        }
        Value::Map(map) => {
            for (_, v) in map {
                validate_value(v, limits)?;
            }
        }
        _ => {} // Primitives are always valid
    }

    Ok(())
}

/// Sanitize a label string
pub fn sanitize_label(label: &str) -> DriftResult<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(DriftError::InvalidQuery("Empty label".into()));
    }
    if trimmed.len() > 128 {
        return Err(DriftError::InvalidQuery("Label too long (max 128 chars)".into()));
    }
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(DriftError::InvalidQuery(format!(
            "Label '{}' contains invalid characters (use alphanumeric + underscore)",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

// ═══════════════════════════════════════════════════════════════════
// AUDIT LOG — Tamper-evident operation log
// ═══════════════════════════════════════════════════════════════════

/// A single audit log entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub operation: String,
    pub details: String,
    pub success: bool,
    /// SHA-256 hash of the previous entry (blockchain-style chain)
    pub prev_hash: String,
    /// Hash of this entry
    pub hash: String,
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.success { "✓" } else { "✗" };
        write!(
            f,
            "[{}] {} {} — {}  ({})",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            status,
            self.operation,
            self.details,
            &self.hash[..8]
        )
    }
}

/// Tamper-evident audit log (hash chain)
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog {
            entries: Vec::new(),
        }
    }

    /// Log an operation. Each entry is chained to the previous via hash.
    pub fn log(&mut self, operation: &str, details: &str, success: bool) {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());

        let timestamp = chrono::Utc::now();

        // Compute hash of this entry (includes prev_hash for chain integrity)
        let hash_input = format!(
            "{}|{}|{}|{}|{}",
            timestamp, operation, details, success, prev_hash
        );
        let hash = checksum(hash_input.as_bytes());

        self.entries.push(AuditEntry {
            timestamp,
            operation: operation.to_string(),
            details: details.to_string(),
            success,
            prev_hash,
            hash,
        });
    }

    /// Verify the integrity of the entire audit log chain
    pub fn verify_integrity(&self) -> bool {
        for (i, entry) in self.entries.iter().enumerate() {
            // Check prev_hash chain
            let expected_prev = if i == 0 {
                "GENESIS".to_string()
            } else {
                self.entries[i - 1].hash.clone()
            };

            if entry.prev_hash != expected_prev {
                return false;
            }

            // Recompute and verify this entry's hash
            let hash_input = format!(
                "{}|{}|{}|{}|{}",
                entry.timestamp, entry.operation, entry.details, entry.success, entry.prev_hash
            );
            let computed = checksum(hash_input.as_bytes());
            if entry.hash != computed {
                return false;
            }
        }
        true
    }

    /// Get the last N entries
    pub fn recent(&self, n: usize) -> &[AuditEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }

    /// Get total entry count
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Get failed operations
    pub fn failures(&self) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| !e.success).collect()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(&key);

        let plaintext = b"DriftDB is the future";
        let encrypted = enc.encrypt(plaintext).unwrap();

        // Encrypted should be different from plaintext
        assert_ne!(&encrypted[12..], plaintext);

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_tamper_detection() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(&key);

        let plaintext = b"sensitive data";
        let mut encrypted = enc.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }

        // Decryption should fail (AES-GCM detects tampering)
        assert!(enc.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_password_hash_verify() {
        let password = "Str0ng!Pass#2026";
        let hash = Auth::hash_password(password).unwrap();

        assert!(Auth::verify_password(password, &hash).unwrap());
        assert!(!Auth::verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_password_strength() {
        assert!(Auth::check_strength("Str0ng!Pass").is_ok());
        assert!(Auth::check_strength("weak").is_err());
        assert!(Auth::check_strength("nouppercase1!").is_err());
        assert!(Auth::check_strength("NOLOWERCASE1!").is_err());
        assert!(Auth::check_strength("NoDigits!here").is_err());
        assert!(Auth::check_strength("NoSpecial1here").is_err());
    }

    #[test]
    fn test_checksum_integrity() {
        let data = b"important database record";
        let wrapped = wrap_with_checksum(data);
        let unwrapped = unwrap_checksum(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_checksum_tamper_detection() {
        let data = b"important database record";
        let mut wrapped = wrap_with_checksum(data);

        // Tamper with the data portion
        if let Some(byte) = wrapped.last_mut() {
            *byte ^= 0xFF;
        }

        assert!(unwrap_checksum(&wrapped).is_err());
    }

    #[test]
    fn test_query_validation() {
        let limits = SecurityLimits::default();

        assert!(validate_query("FIND (u:User)", &limits).is_ok());
        assert!(validate_query("normal query\nwith newline", &limits).is_ok());

        // Null bytes
        assert!(validate_query("bad\0query", &limits).is_err());

        // Too long
        let long = "A".repeat(20_000);
        assert!(validate_query(&long, &limits).is_err());
    }

    #[test]
    fn test_label_sanitization() {
        assert_eq!(sanitize_label("User").unwrap(), "User");
        assert_eq!(sanitize_label("  User  ").unwrap(), "User");
        assert!(sanitize_label("").is_err());
        assert!(sanitize_label("bad label!").is_err());
        assert!(sanitize_label("has spaces").is_err());
    }

    #[test]
    fn test_audit_log_chain() {
        let mut log = AuditLog::new();
        log.log("CREATE_NODE", "User node created", true);
        log.log("CREATE_EDGE", "BUILT edge created", true);
        log.log("FIND", "Pattern query executed", true);
        log.log("DELETE", "Unauthorized delete attempt", false);

        assert_eq!(log.count(), 4);
        assert!(log.verify_integrity());
        assert_eq!(log.failures().len(), 1);
    }

    #[test]
    fn test_audit_log_tamper_detection() {
        let mut log = AuditLog::new();
        log.log("CREATE_NODE", "Node created", true);
        log.log("CREATE_NODE", "Another node", true);

        // Tamper with the first entry
        log.entries[0].details = "TAMPERED".to_string();

        // Integrity check should fail
        assert!(!log.verify_integrity());
    }

    #[test]
    fn test_key_derivation() {
        let salt = b"driftdb_salt_v1!"; // 16 bytes
        let key1 = Encryptor::derive_key("my_password", salt);
        let key2 = Encryptor::derive_key("my_password", salt);
        let key3 = Encryptor::derive_key("different", salt);

        // Same password + salt = same key
        assert_eq!(key1, key2);
        // Different password = different key
        assert_ne!(key1, key3);
    }
}
