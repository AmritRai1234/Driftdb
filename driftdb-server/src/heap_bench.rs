//! DriftDB — Heap Engine Benchmark (Pure In-Memory)
//!
//! This measures the raw throughput of the heap engine:
//! zero disk I/O, zero serialization, pure HashMap operations.

use driftdb_core::heap::HeapEngine;
use driftdb_core::types::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    println!("\n  🧠 DriftDB Heap Engine Benchmark (Pure In-Memory)");
    println!("  ════════════════════════════════════════════════\n");

    let engine = Arc::new(HeapEngine::with_capacity(100_000, 100_000));

    // ─── 1: Bulk Node Creation ────────────────────────────────────
    let count = 100_000;
    let bulk_data: Vec<_> = (0..count)
        .map(|i| {
            (
                vec!["User".to_string()],
                HashMap::from([
                    ("name".to_string(), Value::String(format!("user_{}", i))),
                    ("age".to_string(), Value::Int(20 + (i % 50) as i64)),
                ]),
            )
        })
        .collect();

    let start = Instant::now();
    let nodes = engine.bulk_create_nodes(bulk_data).unwrap();
    let elapsed = start.elapsed();
    let ops = count as f64 / elapsed.as_secs_f64();
    let node_ids: Vec<_> = nodes.iter().map(|n| n.id.clone()).collect();
    println!(
        "  🚀 Bulk Node Create   │ {:>6} nodes  in {:>8.1}ms │ {:>12.0} ops/sec",
        count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 2: Single Node Creation ──────────────────────────────────
    let single_count = 100_000;
    let start = Instant::now();
    for i in 0..single_count {
        engine
            .create_node(
                vec!["Person".to_string()],
                HashMap::from([("n".to_string(), Value::Int(i))]),
            )
            .unwrap();
    }
    let elapsed = start.elapsed();
    let ops = single_count as f64 / elapsed.as_secs_f64();
    println!(
        "  📦 Node Creation      │ {:>6} nodes  in {:>8.1}ms │ {:>12.0} ops/sec",
        single_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 3: Node Lookup (O(1) HashMap) ────────────────────────────
    let lookup_count = 1_000_000;
    let start = Instant::now();
    for i in 0..lookup_count {
        let id = &node_ids[i % node_ids.len()];
        engine.get_node(id).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = lookup_count as f64 / elapsed.as_secs_f64();
    println!(
        "  ⚡ Node Lookup        │ {:>6} reads  in {:>8.1}ms │ {:>12.0} ops/sec",
        lookup_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 4: Existence Check (O(1)) ────────────────────────────────
    let start = Instant::now();
    for i in 0..lookup_count {
        let id = &node_ids[i % node_ids.len()];
        engine.node_exists(id);
    }
    let elapsed = start.elapsed();
    let ops = lookup_count as f64 / elapsed.as_secs_f64();
    println!(
        "  ✓  Existence Check    │ {:>6} checks in {:>7.1}ms │ {:>12.0} ops/sec",
        lookup_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 5: Edge Creation ─────────────────────────────────────────
    let edge_count = 50_000;
    let start = Instant::now();
    for i in 0..edge_count {
        let src = node_ids[i % node_ids.len()].clone();
        let tgt = node_ids[(i + 1) % node_ids.len()].clone();
        engine
            .create_edge(src, tgt, "KNOWS".to_string(), HashMap::new())
            .unwrap();
    }
    let elapsed = start.elapsed();
    let ops = edge_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🔗 Edge Creation      │ {:>6} edges  in {:>8.1}ms │ {:>12.0} ops/sec",
        edge_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 6: Bulk Edge Creation ────────────────────────────────────
    let bulk_edge_count = 50_000;
    let edges_data: Vec<_> = (0..bulk_edge_count)
        .map(|i| {
            let src = node_ids[(i + 2) % node_ids.len()].clone();
            let tgt = node_ids[(i + 3) % node_ids.len()].clone();
            (src, tgt, "FOLLOWS".to_string(), HashMap::new())
        })
        .collect();

    let start = Instant::now();
    engine.bulk_create_edges(edges_data).unwrap();
    let elapsed = start.elapsed();
    let ops = bulk_edge_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🚀 Bulk Edge Create   │ {:>6} edges  in {:>8.1}ms │ {:>12.0} ops/sec",
        bulk_edge_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 7: Count by Label (O(1)) ────────────────────────────────
    let count_ops = 1_000_000;
    let start = Instant::now();
    for _ in 0..count_ops {
        engine.count_by_label("user");
    }
    let elapsed = start.elapsed();
    let ops = count_ops as f64 / elapsed.as_secs_f64();
    println!(
        "  🔢 Count by Label     │ {:>6} counts in {:>7.1}ms │ {:>12.0} ops/sec",
        count_ops, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── 8: Label Query ───────────────────────────────────────────
    let start = Instant::now();
    let users = engine.nodes_by_label("User").unwrap();
    let elapsed = start.elapsed();
    println!(
        "  🏷️  Label Query        │ {:>6} nodes  in {:>8.1}ms │ in-memory scan",
        users.len(), elapsed.as_secs_f64() * 1000.0,
    );

    // ─── 9: Vector Attach ─────────────────────────────────────────
    let vec_count = 10_000;
    let dims = 128;
    let start = Instant::now();
    for i in 0..vec_count {
        let vec_data: Vec<f64> = (0..dims).map(|d| ((i * dims + d) as f64).sin()).collect();
        engine.attach_vector(&node_ids[i], vec_data).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = vec_count as f64 / elapsed.as_secs_f64();
    println!(
        "  📐 Vector Attach      │ {:>6} vecs   in {:>8.1}ms │ {:>12.0} ops/sec ({}D)",
        vec_count, elapsed.as_secs_f64() * 1000.0, ops, dims
    );

    // ─── 10: Concurrent Reads (8 threads) ─────────────────────────
    let thread_count = 8;
    let reads_per_thread = 100_000;
    let total_reads = thread_count * reads_per_thread;

    let start = Instant::now();
    let mut handles = Vec::new();
    for t in 0..thread_count {
        let e = engine.clone();
        let ids = node_ids.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..reads_per_thread {
                let id = &ids[(t * reads_per_thread + i) % ids.len()];
                e.get_node(id).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();
    let ops = total_reads as f64 / elapsed.as_secs_f64();
    println!(
        "  🧵 Concurrent Reads   │ {:>6} reads  in {:>8.1}ms │ {:>12.0} ops/sec ({}T)",
        total_reads, elapsed.as_secs_f64() * 1000.0, ops, thread_count
    );

    // ─── Summary ──────────────────────────────────────────────────
    let stats = engine.stats();
    let mem_mb = engine.memory_usage() as f64 / (1024.0 * 1024.0);
    println!("\n  ════════════════════════════════════════════════");
    println!("  📈 Final: {} | ~{:.1} MB RAM", stats, mem_mb);
    println!("  🧠 Pure heap memory — zero disk I/O — zero serialization\n");
}
