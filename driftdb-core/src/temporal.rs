//! DriftDB Core — Temporal versioning engine
//!
//! Nothing is ever deleted in DriftDB. Every mutation creates a new version
//! with a timestamp. Old versions are marked as expired. You can query
//! the state of any piece of data at any point in time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DriftResult;
use crate::types::TemporalMeta;

/// A versioned wrapper around any value.
/// Stores a stack of versions, each with temporal metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedValue<T: Clone + Serialize> {
    pub versions: Vec<VersionEntry<T>>,
}

/// A single version entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEntry<T: Clone + Serialize> {
    pub value: T,
    pub temporal: TemporalMeta,
}

/// Maximum versions stored per value (prevents memory bomb from rapid updates)
const MAX_VERSIONS: usize = 1000;

impl<T: Clone + Serialize + for<'de> Deserialize<'de>> VersionedValue<T> {
    /// Create a new versioned value with an initial version
    pub fn new(value: T) -> Self {
        VersionedValue {
            versions: vec![VersionEntry {
                value,
                temporal: TemporalMeta::now(1),
            }],
        }
    }

    /// Get the current (latest non-expired) version
    pub fn current(&self) -> Option<&T> {
        self.versions
            .iter()
            .rev()
            .find(|v| v.temporal.is_current())
            .map(|v| &v.value)
    }

    /// Get the value at a specific point in time
    pub fn at(&self, timestamp: &DateTime<Utc>) -> Option<&T> {
        self.versions
            .iter()
            .rev()
            .find(|v| v.temporal.active_at(timestamp))
            .map(|v| &v.value)
    }

    /// Push a new version, expiring the current one.
    ///
    /// SECURITY: Capped at MAX_VERSIONS to prevent memory bomb.
    /// An AI could loop rapid updates to grow version history unbounded.
    pub fn update(&mut self, value: T) -> DriftResult<()> {
        // Expire the current version
        if let Some(current) = self.versions.iter_mut().rev().find(|v| v.temporal.is_current()) {
            current.temporal.expire();
        }

        let next_version = self.versions.len() as u64 + 1;
        self.versions.push(VersionEntry {
            value,
            temporal: TemporalMeta::now(next_version),
        });

        // Evict oldest versions if over cap (keep first + most recent)
        if self.versions.len() > MAX_VERSIONS {
            // Keep the first version (creation snapshot) and trim from position 1
            let excess = self.versions.len() - MAX_VERSIONS;
            self.versions.drain(1..1 + excess);
        }

        Ok(())
    }

    /// Soft-delete: expire the current version without adding a new one
    pub fn soft_delete(&mut self) {
        if let Some(current) = self.versions.iter_mut().rev().find(|v| v.temporal.is_current()) {
            current.temporal.expire();
        }
    }

    /// Get the full version history
    pub fn history(&self) -> &[VersionEntry<T>] {
        &self.versions
    }

    /// Get version count
    pub fn version_count(&self) -> usize {
        self.versions.len()
    }

    /// Check if this value is currently active (not deleted)
    pub fn is_active(&self) -> bool {
        self.current().is_some()
    }
}

/// Temporal query parameters
#[derive(Debug, Clone)]
pub enum TemporalQuery {
    /// Get the current state
    Current,
    /// Get state at a specific timestamp
    At(DateTime<Utc>),
    /// Get state within a time range
    Between(DateTime<Utc>, DateTime<Utc>),
    /// Get full history
    History,
}

impl TemporalQuery {
    /// Parse a time-travel query from a string
    pub fn parse(input: &str) -> DriftResult<Self> {
        let input = input.trim();
        if input.eq_ignore_ascii_case("current") || input.is_empty() {
            return Ok(TemporalQuery::Current);
        }
        if input.eq_ignore_ascii_case("history") {
            return Ok(TemporalQuery::History);
        }

        // Try to parse as a single timestamp
        if let Ok(ts) = input.parse::<DateTime<Utc>>() {
            return Ok(TemporalQuery::At(ts));
        }

        // Try to parse as a range "t1..t2"
        if let Some((start, end)) = input.split_once("..") {
            let start = start
                .trim()
                .parse::<DateTime<Utc>>()
                .map_err(|e| crate::error::DriftError::InvalidQuery(format!("Invalid start timestamp: {}", e)))?;
            let end = end
                .trim()
                .parse::<DateTime<Utc>>()
                .map_err(|e| crate::error::DriftError::InvalidQuery(format!("Invalid end timestamp: {}", e)))?;
            return Ok(TemporalQuery::Between(start, end));
        }

        Err(crate::error::DriftError::InvalidQuery(format!(
            "Cannot parse temporal query: '{}'",
            input
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_versioned_value_basic() {
        let vv = VersionedValue::new(42i64);
        assert_eq!(vv.current(), Some(&42));
        assert_eq!(vv.version_count(), 1);
        assert!(vv.is_active());
    }

    #[test]
    fn test_versioned_value_update() {
        let mut vv = VersionedValue::new("hello".to_string());
        sleep(Duration::from_millis(10));

        vv.update("world".to_string()).unwrap();
        assert_eq!(vv.current(), Some(&"world".to_string()));
        assert_eq!(vv.version_count(), 2);
    }

    #[test]
    fn test_versioned_value_time_travel() {
        let mut vv = VersionedValue::new("v1".to_string());
        let t1 = Utc::now();
        sleep(Duration::from_millis(20));

        vv.update("v2".to_string()).unwrap();
        sleep(Duration::from_millis(20));

        // Current should be v2
        assert_eq!(vv.current(), Some(&"v2".to_string()));

        // At t1 should be v1
        assert_eq!(vv.at(&t1), Some(&"v1".to_string()));
    }

    #[test]
    fn test_soft_delete() {
        let mut vv = VersionedValue::new(100i64);
        vv.soft_delete();
        assert!(vv.current().is_none());
        assert!(!vv.is_active());
        // But history is preserved
        assert_eq!(vv.version_count(), 1);
    }

    #[test]
    fn test_temporal_query_parse() {
        assert!(matches!(
            TemporalQuery::parse("current").unwrap(),
            TemporalQuery::Current
        ));
        assert!(matches!(
            TemporalQuery::parse("history").unwrap(),
            TemporalQuery::History
        ));
        assert!(matches!(
            TemporalQuery::parse("").unwrap(),
            TemporalQuery::Current
        ));
    }
}
