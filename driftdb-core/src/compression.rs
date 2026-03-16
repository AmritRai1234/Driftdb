//! DriftDB — Data Compression Engine
//!
//! LZ4 compression for stored values. Reduces disk footprint
//! without sacrificing read speed (LZ4 decompresses at ~4 GB/s).

use crate::error::{DriftError, DriftResult};

/// Compression format marker (first byte of stored data)
const COMPRESSED_MARKER: u8 = 0xC0;
const UNCOMPRESSED_MARKER: u8 = 0x00;

/// Minimum size threshold for compression (don't compress tiny values)
const MIN_COMPRESS_SIZE: usize = 64;

/// Compress data using LZ4
pub fn compress(data: &[u8]) -> Vec<u8> {
    if data.len() < MIN_COMPRESS_SIZE {
        // Too small to benefit — store raw with marker
        let mut result = Vec::with_capacity(1 + data.len());
        result.push(UNCOMPRESSED_MARKER);
        result.extend_from_slice(data);
        return result;
    }

    let compressed = lz4_flex::compress_prepend_size(data);

    // Only use compression if it actually saves space
    if compressed.len() < data.len() {
        let mut result = Vec::with_capacity(1 + compressed.len());
        result.push(COMPRESSED_MARKER);
        result.extend_from_slice(&compressed);
        result
    } else {
        let mut result = Vec::with_capacity(1 + data.len());
        result.push(UNCOMPRESSED_MARKER);
        result.extend_from_slice(data);
        result
    }
}

/// Decompress data (auto-detects format from marker byte)
pub fn decompress(data: &[u8]) -> DriftResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    match data[0] {
        COMPRESSED_MARKER => {
            lz4_flex::decompress_size_prepended(&data[1..])
                .map_err(|e| DriftError::Internal(format!("Decompression failed: {}", e)))
        }
        UNCOMPRESSED_MARKER => {
            Ok(data[1..].to_vec())
        }
        _ => {
            // Legacy: assume uncompressed data without marker
            Ok(data.to_vec())
        }
    }
}

/// Get compression ratio for a piece of data
pub fn compression_ratio(original: &[u8]) -> f64 {
    let compressed = compress(original);
    compressed.len() as f64 / original.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_small() {
        // Small data should be stored uncompressed
        let data = b"hello";
        let compressed = compress(data);
        assert_eq!(compressed[0], UNCOMPRESSED_MARKER);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_decompress_large() {
        // Large repetitive data should compress well
        let data: Vec<u8> = "ABCDEFGHIJ".repeat(100).into_bytes();
        let compressed = compress(&data);

        // Should be compressed
        assert_eq!(compressed[0], COMPRESSED_MARKER);
        // Should be smaller
        assert!(compressed.len() < data.len());

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_ratio() {
        let repetitive = "hello world ".repeat(1000).into_bytes();
        let ratio = compression_ratio(&repetitive);
        assert!(ratio < 0.1); // Should compress to less than 10%

        let random: Vec<u8> = (0..1000u16).map(|i| (i * 7 + 13) as u8).collect();
        let ratio = compression_ratio(&random);
        // Random data doesn't compress well, but we still handle it
        assert!(ratio > 0.0);
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let compressed = compress(data);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
