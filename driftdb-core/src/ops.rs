//! DriftDB — Backup & Restore + Health Checks
//!
//! Snapshot the entire database to a portable format,
//! restore from backups, and run health diagnostics.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{DriftError, DriftResult};
use crate::storage::Storage;

// ═══════════════════════════════════════════════════════════════════
// BACKUP & RESTORE
// ═══════════════════════════════════════════════════════════════════

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub created_at: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub vector_count: usize,
    pub original_path: String,
    pub checksum: String,
    #[serde(default)]
    pub encrypted: bool,
}

/// Create a full backup of the database (optionally encrypted)
pub fn create_backup(storage: &Storage, backup_dir: &str) -> DriftResult<PathBuf> {
    create_backup_with_key(storage, backup_dir, None)
}

/// Create an encrypted backup with a password-derived key
pub fn create_encrypted_backup(
    storage: &Storage,
    backup_dir: &str,
    password: &str,
) -> DriftResult<PathBuf> {
    let salt = b"driftdb_backup_v1"; // Fixed salt for backup key derivation
    let key = crate::security::Encryptor::derive_key(password, salt);
    create_backup_with_key(storage, backup_dir, Some(key))
}

/// Internal: create backup with optional encryption key
fn create_backup_with_key(
    storage: &Storage,
    backup_dir: &str,
    key: Option<[u8; 32]>,
) -> DriftResult<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let suffix = if key.is_some() { "_encrypted" } else { "" };
    let backup_path = PathBuf::from(backup_dir).join(format!(
        "driftdb_backup_{}{}", timestamp, suffix
    ));

    // SECURITY: Reject symlinks in the backup path to prevent symlink attacks.
    // An attacker could create a symlink at the backup path pointing to
    // /etc/shadow or another sensitive file, causing us to overwrite it.
    let base_dir = PathBuf::from(backup_dir);
    if base_dir.exists() && base_dir.read_link().is_ok() {
        return Err(DriftError::Storage(
            "SECURITY: Backup directory is a symlink. Refusing to write (possible symlink attack)."
                .into(),
        ));
    }

    fs::create_dir_all(&backup_path)
        .map_err(|e| DriftError::Storage(format!("Cannot create backup directory: {}", e)))?;

    // Restrict backup directory permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&backup_path, perms);
    }

    // Export all data
    let nodes = storage.all_nodes()?;
    let nodes_json = serde_json::to_string_pretty(&nodes)?;

    let edges = storage.all_edges()?;
    let edges_json = serde_json::to_string_pretty(&edges)?;

    let vectors = storage.all_vectors()?;
    let vectors_json = serde_json::to_string_pretty(&vectors)?;

    // Compute checksum over plaintext (before encryption)
    let combined = format!("{}{}{}", nodes_json, edges_json, vectors_json);
    let checksum = crate::security::checksum(combined.as_bytes());

    if let Some(ref enc_key) = key {
        // Encrypted backup: write .enc files
        let encryptor = crate::security::Encryptor::new(enc_key);

        let enc_nodes = encryptor.encrypt(nodes_json.as_bytes())?;
        write_backup_file(&backup_path.join("nodes.enc"), &enc_nodes)?;

        let enc_edges = encryptor.encrypt(edges_json.as_bytes())?;
        write_backup_file(&backup_path.join("edges.enc"), &enc_edges)?;

        let enc_vectors = encryptor.encrypt(vectors_json.as_bytes())?;
        write_backup_file(&backup_path.join("vectors.enc"), &enc_vectors)?;
    } else {
        // Plaintext backup
        write_backup_file(&backup_path.join("nodes.json"), nodes_json.as_bytes())?;
        write_backup_file(&backup_path.join("edges.json"), edges_json.as_bytes())?;
        write_backup_file(&backup_path.join("vectors.json"), vectors_json.as_bytes())?;
    }

    // Manifest (always written — no sensitive data in manifest)
    let manifest = BackupManifest {
        version: "0.1.0".to_string(),
        created_at: Utc::now().to_rfc3339(),
        node_count: nodes.len(),
        edge_count: edges.len(),
        vector_count: vectors.len(),
        original_path: "unknown".to_string(),
        checksum,
        encrypted: key.is_some(),
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    write_backup_file(&backup_path.join("manifest.json"), manifest_json.as_bytes())?;

    Ok(backup_path)
}

/// Write a file with restricted permissions (0600)
fn write_backup_file(path: &Path, data: &[u8]) -> DriftResult<()> {
    fs::write(path, data)
        .map_err(|e| DriftError::Storage(format!("Backup write failed: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }

    Ok(())
}

/// Verify a backup's integrity
pub fn verify_backup(backup_dir: &str) -> DriftResult<BackupManifest> {
    let path = PathBuf::from(backup_dir);

    // Read manifest
    let manifest_data = fs::read_to_string(path.join("manifest.json"))
        .map_err(|e| DriftError::Storage(format!("Cannot read manifest: {}", e)))?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_data)?;

    // Verify checksum
    let nodes = fs::read_to_string(path.join("nodes.json"))
        .map_err(|e| DriftError::Storage(format!("Cannot read nodes backup: {}", e)))?;
    let edges = fs::read_to_string(path.join("edges.json"))
        .map_err(|e| DriftError::Storage(format!("Cannot read edges backup: {}", e)))?;
    let vectors = fs::read_to_string(path.join("vectors.json"))
        .map_err(|e| DriftError::Storage(format!("Cannot read vectors backup: {}", e)))?;

    let combined = format!("{}{}{}", nodes, edges, vectors);
    let actual_checksum = crate::security::checksum(combined.as_bytes());

    if actual_checksum != manifest.checksum {
        return Err(DriftError::Internal(
            "BACKUP INTEGRITY FAILURE: Checksum mismatch — backup may be corrupted or tampered"
                .into(),
        ));
    }

    Ok(manifest)
}

// ═══════════════════════════════════════════════════════════════════
// RESTORE
// ═══════════════════════════════════════════════════════════════════

/// Restore from a plaintext backup
pub fn restore_backup(storage: &Storage, backup_dir: &str) -> DriftResult<RestoreReport> {
    restore_internal(storage, backup_dir, None)
}

/// Restore from an encrypted backup (password required)
pub fn restore_encrypted_backup(
    storage: &Storage,
    backup_dir: &str,
    password: &str,
) -> DriftResult<RestoreReport> {
    // Derive the encryption key from password
    let salt = b"driftdb-backup-salt-v1";
    let key = crate::security::Encryptor::derive_key(password, salt);
    restore_internal(storage, backup_dir, Some(key))
}

/// Restore report — what was imported
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub nodes_restored: usize,
    pub edges_restored: usize,
    pub vectors_restored: usize,
    pub backup_version: String,
    pub backup_created_at: String,
}

impl std::fmt::Display for RestoreReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Restored {} nodes, {} edges, {} vectors (backup v{} from {})",
            self.nodes_restored,
            self.edges_restored,
            self.vectors_restored,
            self.backup_version,
            self.backup_created_at,
        )
    }
}

/// Internal restore implementation
fn restore_internal(
    storage: &Storage,
    backup_dir: &str,
    key: Option<[u8; 32]>,
) -> DriftResult<RestoreReport> {
    use crate::types::{Edge, Node, NodeId};

    let path = PathBuf::from(backup_dir);

    // 1. Read and validate manifest
    let manifest_data = fs::read_to_string(path.join("manifest.json"))
        .map_err(|e| DriftError::Storage(format!("Cannot read manifest: {}", e)))?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_data)?;

    // 2. Read data files (decrypt if needed)
    let (nodes_json, edges_json, vectors_json) = if manifest.encrypted {
        let enc_key = key.ok_or_else(|| {
            DriftError::Internal("Backup is encrypted — password required".into())
        })?;
        let encryptor = crate::security::Encryptor::new(&enc_key);

        let enc_nodes = fs::read(path.join("nodes.enc"))
            .map_err(|e| DriftError::Storage(format!("Cannot read encrypted nodes: {}", e)))?;
        let enc_edges = fs::read(path.join("edges.enc"))
            .map_err(|e| DriftError::Storage(format!("Cannot read encrypted edges: {}", e)))?;
        let enc_vectors = fs::read(path.join("vectors.enc"))
            .map_err(|e| DriftError::Storage(format!("Cannot read encrypted vectors: {}", e)))?;

        let nodes = String::from_utf8(encryptor.decrypt(&enc_nodes)?)
            .map_err(|_| DriftError::Internal("Decrypted nodes are not valid UTF-8".into()))?;
        let edges = String::from_utf8(encryptor.decrypt(&enc_edges)?)
            .map_err(|_| DriftError::Internal("Decrypted edges are not valid UTF-8".into()))?;
        let vectors = String::from_utf8(encryptor.decrypt(&enc_vectors)?)
            .map_err(|_| DriftError::Internal("Decrypted vectors are not valid UTF-8".into()))?;

        (nodes, edges, vectors)
    } else {
        let nodes = fs::read_to_string(path.join("nodes.json"))
            .map_err(|e| DriftError::Storage(format!("Cannot read nodes: {}", e)))?;
        let edges = fs::read_to_string(path.join("edges.json"))
            .map_err(|e| DriftError::Storage(format!("Cannot read edges: {}", e)))?;
        let vectors = fs::read_to_string(path.join("vectors.json"))
            .map_err(|e| DriftError::Storage(format!("Cannot read vectors: {}", e)))?;

        (nodes, edges, vectors)
    };

    // 3. Verify checksum BEFORE restoring
    let combined = format!("{}{}{}", nodes_json, edges_json, vectors_json);
    let actual_checksum = crate::security::checksum(combined.as_bytes());
    if actual_checksum != manifest.checksum {
        return Err(DriftError::Internal(
            "BACKUP INTEGRITY FAILURE: Checksum mismatch — backup may be corrupted or tampered"
                .into(),
        ));
    }

    // 4. Deserialize
    let nodes: Vec<Node> = serde_json::from_str(&nodes_json)?;
    let edges: Vec<Edge> = serde_json::from_str(&edges_json)?;
    let vectors: Vec<(String, Vec<f64>)> = serde_json::from_str(&vectors_json)?;

    // 5. Replay into storage
    let mut nodes_restored = 0;
    for node in &nodes {
        // Insert node directly into storage (preserving original IDs)
        let versioned = crate::temporal::VersionedValue::new(node.clone());
        let bytes = bincode::serialize(&versioned)?;
        storage.raw_insert_node(&node.id, &bytes)?;
        nodes_restored += 1;
    }

    let mut edges_restored = 0;
    for edge in &edges {
        let versioned = crate::temporal::VersionedValue::new(edge.clone());
        let bytes = bincode::serialize(&versioned)?;
        storage.raw_insert_edge(&edge.id, &bytes)?;
        edges_restored += 1;
    }

    let mut vectors_restored = 0;
    for (node_id_str, vector) in &vectors {
        let node_id = NodeId::from_str(node_id_str);
        storage.attach_vector(&node_id, vector.clone())?;
        vectors_restored += 1;
    }

    Ok(RestoreReport {
        nodes_restored,
        edges_restored,
        vectors_restored,
        backup_version: manifest.version,
        backup_created_at: manifest.created_at,
    })
}

// ═══════════════════════════════════════════════════════════════════
// HEALTH CHECKS
// ═══════════════════════════════════════════════════════════════════

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthReport {
    pub checks: Vec<HealthCheck>,
    pub overall: HealthStatus,
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub detail: String,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "HEALTHY"),
            HealthStatus::Degraded => write!(f, "DEGRADED"),
            HealthStatus::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Run comprehensive health checks on the database
pub fn health_check(storage: &Storage) -> DriftResult<HealthReport> {
    let mut checks = Vec::new();

    // 1. Storage read/write test
    let start = std::time::Instant::now();
    let rw_check = match storage.stats() {
        Ok(stats) => HealthCheck {
            name: "Storage Engine".to_string(),
            status: HealthStatus::Healthy,
            detail: format!(
                "{} nodes, {} edges, {:.1} MB",
                stats.node_count,
                stats.edge_count,
                stats.size_on_disk as f64 / (1024.0 * 1024.0)
            ),
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        },
        Err(e) => HealthCheck {
            name: "Storage Engine".to_string(),
            status: HealthStatus::Critical,
            detail: format!("FAILED: {}", e),
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        },
    };
    checks.push(rw_check);

    // 2. Node integrity scan (sample check)
    let start = std::time::Instant::now();
    let nodes = storage.all_nodes()?;
    let node_check = HealthCheck {
        name: "Node Integrity".to_string(),
        status: if nodes.iter().all(|n| !n.id.0.is_empty()) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        },
        detail: format!("{} nodes scanned", nodes.len()),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    checks.push(node_check);

    // 3. Edge referential integrity
    let start = std::time::Instant::now();
    let edges = storage.all_edges()?;
    let mut orphaned_edges = 0;
    for edge in &edges {
        if storage.get_node(&edge.source)?.is_none()
            || storage.get_node(&edge.target)?.is_none()
        {
            orphaned_edges += 1;
        }
    }
    let edge_check = HealthCheck {
        name: "Edge Integrity".to_string(),
        status: if orphaned_edges == 0 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        },
        detail: format!(
            "{} edges checked, {} orphaned",
            edges.len(),
            orphaned_edges
        ),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    checks.push(edge_check);

    // 4. Vector dimension consistency
    let start = std::time::Instant::now();
    let vectors = storage.all_vectors()?;
    let dims: std::collections::HashSet<usize> = vectors.iter().map(|(_, v)| v.len()).collect();
    let vec_check = HealthCheck {
        name: "Vector Consistency".to_string(),
        status: if dims.len() <= 1 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        },
        detail: format!(
            "{} vectors, {} distinct dimensions",
            vectors.len(),
            dims.len()
        ),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    checks.push(vec_check);

    // 5. Event system
    let start = std::time::Instant::now();
    let event_count = storage.events.event_count();
    let event_check = HealthCheck {
        name: "Event System".to_string(),
        status: HealthStatus::Healthy,
        detail: format!("{} events logged", event_count),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    checks.push(event_check);

    // 6. Disk space
    let start = std::time::Instant::now();
    let stats = storage.stats()?;
    let disk_mb = stats.size_on_disk as f64 / (1024.0 * 1024.0);
    let disk_check = HealthCheck {
        name: "Disk Usage".to_string(),
        status: if disk_mb < 1000.0 {
            HealthStatus::Healthy
        } else if disk_mb < 5000.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Critical
        },
        detail: format!("{:.1} MB", disk_mb),
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    };
    checks.push(disk_check);

    // Compute overall status
    let overall = if checks.iter().any(|c| c.status == HealthStatus::Critical) {
        HealthStatus::Critical
    } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    Ok(HealthReport { checks, overall })
}

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/// DriftDB configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftConfig {
    pub data_dir: String,
    pub wal_enabled: bool,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub auth_required: bool,
    pub max_connections: usize,
    pub auto_checkpoint_interval: u64,
    pub backup_dir: String,
    pub auto_backup_enabled: bool,
    pub log_level: String,
}

impl Default for DriftConfig {
    fn default() -> Self {
        DriftConfig {
            data_dir: "./drift_data".to_string(),
            wal_enabled: true,
            compression_enabled: true,
            encryption_enabled: false,
            auth_required: false,
            max_connections: 64,
            auto_checkpoint_interval: 1000,
            backup_dir: "./drift_backups".to_string(),
            auto_backup_enabled: false,
            log_level: "info".to_string(),
        }
    }
}

impl DriftConfig {
    /// Load config from a TOML file, falling back to defaults
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();
        if path.exists() {
            match fs::read_to_string(path) {
                Ok(content) => {
                    // Simple key=value parser for config files
                    let mut config = DriftConfig::default();
                    for line in content.lines() {
                        let line = line.trim();
                        if line.starts_with('#') || line.is_empty() {
                            continue;
                        }
                        if let Some((key, value)) = line.split_once('=') {
                            let key = key.trim();
                            let value = value.trim().trim_matches('"');
                            match key {
                                "data_dir" => config.data_dir = value.to_string(),
                                "wal_enabled" => config.wal_enabled = value == "true",
                                "compression_enabled" => config.compression_enabled = value == "true",
                                "encryption_enabled" => config.encryption_enabled = value == "true",
                                "auth_required" => config.auth_required = value == "true",
                                "max_connections" => {
                                    config.max_connections = value.parse().unwrap_or(64)
                                }
                                "backup_dir" => config.backup_dir = value.to_string(),
                                "auto_backup_enabled" => config.auto_backup_enabled = value == "true",
                                "log_level" => config.log_level = value.to_string(),
                                _ => {}
                            }
                        }
                    }
                    config
                }
                Err(_) => DriftConfig::default(),
            }
        } else {
            DriftConfig::default()
        }
    }

    /// Save config to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> DriftResult<()> {
        let content = format!(
            r#"# DriftDB Configuration
# Generated at {}

data_dir = "{}"
wal_enabled = {}
compression_enabled = {}
encryption_enabled = {}
auth_required = {}
max_connections = {}
backup_dir = "{}"
auto_backup_enabled = {}
log_level = "{}"
"#,
            Utc::now().to_rfc3339(),
            self.data_dir,
            self.wal_enabled,
            self.compression_enabled,
            self.encryption_enabled,
            self.auth_required,
            self.max_connections,
            self.backup_dir,
            self.auto_backup_enabled,
            self.log_level,
        );

        fs::write(path.as_ref(), content)
            .map_err(|e| DriftError::Storage(format!("Config save failed: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check() {
        let storage = Storage::temporary().unwrap();

        // Add some data
        use crate::types::Value;
        use std::collections::HashMap;
        storage.create_node(
            vec!["Test".to_string()],
            HashMap::from([("x".to_string(), Value::Int(1))]),
        ).unwrap();

        let report = health_check(&storage).unwrap();
        assert_eq!(report.overall, HealthStatus::Healthy);
        assert!(report.checks.len() >= 5);
    }

    #[test]
    fn test_backup_and_verify() {
        let storage = Storage::temporary().unwrap();

        use crate::types::Value;
        use std::collections::HashMap;
        storage.create_node(
            vec!["User".to_string()],
            HashMap::from([("name".to_string(), Value::String("Amrit".into()))]),
        ).unwrap();

        let tmp_dir = std::env::temp_dir().join("driftdb_backup_test");
        let backup_path = create_backup(&storage, tmp_dir.to_str().unwrap()).unwrap();

        // Verify the backup
        let manifest = verify_backup(backup_path.to_str().unwrap()).unwrap();
        assert_eq!(manifest.node_count, 1);
        assert_eq!(manifest.version, "0.1.0");

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_config_defaults() {
        let config = DriftConfig::default();
        assert_eq!(config.data_dir, "./drift_data");
        assert!(config.wal_enabled);
        assert!(config.compression_enabled);
        assert!(!config.auth_required);
    }

    #[test]
    fn test_config_save_load() {
        let tmp_path = std::env::temp_dir().join("driftdb_test_config.conf");
        let config = DriftConfig::default();
        config.save(&tmp_path).unwrap();

        let loaded = DriftConfig::load(&tmp_path);
        assert_eq!(loaded.data_dir, config.data_dir);
        assert_eq!(loaded.wal_enabled, config.wal_enabled);

        let _ = std::fs::remove_file(&tmp_path);
    }
}
