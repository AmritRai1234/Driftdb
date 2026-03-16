//! DriftDB Performance Benchmark (Maximum Performance)

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use driftdb_core::types::Value;
use driftdb_core::Storage;
use driftdb_graph::GraphEngine;
use driftdb_vector::VectorEngine;
use driftdb_query::Executor;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    println!("\n  ⚡ DriftDB Performance Benchmark (Maximum Performance)");
    println!("  ════════════════════════════════════════════════\n");

    let storage = Arc::new(Storage::temporary().unwrap());
    let graph = Arc::new(GraphEngine::new(storage.clone()));
    let vector = Arc::new(VectorEngine::new(storage.clone()));

    // ─── Benchmark 1: Bulk Node Creation ──────────────────────────
    let count = 10_000;
    let bulk_data: Vec<(Vec<String>, HashMap<String, Value>)> = (0..count)
        .map(|i| {
            let props = HashMap::from([
                ("name".to_string(), Value::String(format!("user_{}", i))),
                ("age".to_string(), Value::Int(20 + (i % 50) as i64)),
                ("score".to_string(), Value::Float(i as f64 * 0.1)),
            ]);
            (vec!["User".to_string()], props)
        })
        .collect();

    let start = Instant::now();
    let nodes = storage.bulk_create_nodes(bulk_data).unwrap();
    let elapsed = start.elapsed();
    let ops = count as f64 / elapsed.as_secs_f64();
    let node_ids: Vec<_> = nodes.iter().map(|n| n.id.clone()).collect();
    println!(
        "  🚀 Bulk Node Create   │ {:>6} nodes  in {:>8.1}ms │ {:>12.0} ops/sec",
        count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 2: Individual Node Creation ────────────────────
    let single_count = 10_000;
    let start = Instant::now();
    let mut extra_ids = Vec::new();

    for i in 0..single_count {
        let props = HashMap::from([
            ("name".to_string(), Value::String(format!("single_{}", i))),
        ]);
        let node = graph.create_node(vec!["Person".to_string()], props).unwrap();
        extra_ids.push(node.id);
    }

    let elapsed = start.elapsed();
    let ops = single_count as f64 / elapsed.as_secs_f64();
    println!(
        "  📦 Node Creation      │ {:>6} nodes  in {:>8.1}ms │ {:>12.0} ops/sec",
        single_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 3: Edge Creation ───────────────────────────────
    let edge_count = 5_000;
    let start = Instant::now();

    for i in 0..edge_count {
        let src = node_ids[i % node_ids.len()].clone();
        let tgt = node_ids[(i + 1) % node_ids.len()].clone();
        graph.create_edge(src, tgt, "KNOWS".to_string(), HashMap::new()).unwrap();
    }

    let elapsed = start.elapsed();
    let ops = edge_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🔗 Edge Creation      │ {:>6} edges  in {:>8.1}ms │ {:>12.0} ops/sec",
        edge_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 4: Bulk Edge Creation ──────────────────────────
    let bulk_count = 5_000;
    let edges_data: Vec<_> = (0..bulk_count)
        .map(|i| {
            let src = node_ids[(i + 2) % node_ids.len()].clone();
            let tgt = node_ids[(i + 3) % node_ids.len()].clone();
            (src, tgt, "FOLLOWS".to_string(), HashMap::new())
        })
        .collect();

    let start = Instant::now();
    storage.bulk_create_edges(edges_data).unwrap();
    let elapsed = start.elapsed();
    let ops = bulk_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🚀 Bulk Edge Create   │ {:>6} edges  in {:>8.1}ms │ {:>12.0} ops/sec",
        bulk_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 5: Node Lookup — Cache Hit ─────────────────────
    let lookup_count = 10_000;
    // Warm cache
    for i in 0..std::cmp::min(1024, node_ids.len()) {
        let _ = storage.get_node(&node_ids[i]);
    }
    let start = Instant::now();
    for i in 0..lookup_count {
        let id = &node_ids[i % std::cmp::min(1024, node_ids.len())];
        storage.get_node(id).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = lookup_count as f64 / elapsed.as_secs_f64();
    println!(
        "  ⚡ Cached Lookup      │ {:>6} reads  in {:>8.1}ms │ {:>12.0} ops/sec",
        lookup_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 6: Node Lookup — Cold (all IDs) ────────────────
    let start = Instant::now();
    for i in 0..lookup_count {
        let id = &node_ids[i % node_ids.len()];
        graph.get_node(id).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = lookup_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🔍 Cold Lookup        │ {:>6} reads  in {:>8.1}ms │ {:>12.0} ops/sec",
        lookup_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 7: Label Index Query ───────────────────────────
    let start = Instant::now();
    let users = graph.nodes_by_label("User").unwrap();
    let elapsed = start.elapsed();
    println!(
        "  🏷️  Label Query        │ {:>6} nodes  in {:>8.1}ms │ index scan",
        users.len(), elapsed.as_secs_f64() * 1000.0,
    );

    // ─── Benchmark 8: Count by Label (no deserialization) ─────────
    let start = Instant::now();
    for _ in 0..1000 {
        storage.count_by_label("user").unwrap();
    }
    let elapsed = start.elapsed();
    let ops = 1000.0 / elapsed.as_secs_f64();
    println!(
        "  🔢 Count by Label     │ {:>6} counts in {:>7.1}ms │ {:>12.0} ops/sec",
        1000, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 9: node_exists (zero deserialize) ──────────────
    let start = Instant::now();
    for i in 0..lookup_count {
        let id = &node_ids[i % node_ids.len()];
        storage.node_exists(id).unwrap();
    }
    let elapsed = start.elapsed();
    let ops = lookup_count as f64 / elapsed.as_secs_f64();
    println!(
        "  ✓  Existence Check    │ {:>6} checks in {:>7.1}ms │ {:>12.0} ops/sec",
        lookup_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 10: BFS Traversal ──────────────────────────────
    let start = Instant::now();
    let bfs_result = graph.bfs(&node_ids[0], Some(3)).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  🌊 BFS (depth=3)      │ {:>6} nodes  in {:>8.1}ms │ from single root",
        bfs_result.len(), elapsed.as_secs_f64() * 1000.0,
    );

    // ─── Benchmark 11: Shortest Path ──────────────────────────────
    let start = Instant::now();
    let path = graph.shortest_path(&node_ids[0], &node_ids[100]).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  🛤️  Shortest Path      │   len={:<4} in {:>8.1}ms │ between 2 nodes",
        path.map(|p| p.len()).unwrap_or(0), elapsed.as_secs_f64() * 1000.0,
    );

    // ─── Benchmark 12: Vector Operations ──────────────────────────
    let vec_count = 1_000;
    let dims = 128;
    let start = Instant::now();

    for i in 0..vec_count {
        let vec_data: Vec<f64> = (0..dims).map(|d| ((i * dims + d) as f64).sin()).collect();
        vector.attach(&node_ids[i], vec_data).unwrap();
    }

    let elapsed = start.elapsed();
    let ops = vec_count as f64 / elapsed.as_secs_f64();
    println!(
        "  📐 Vector Attach      │ {:>6} vecs   in {:>8.1}ms │ {:>12.0} ops/sec ({}D)",
        vec_count, elapsed.as_secs_f64() * 1000.0, ops, dims
    );

    // ─── Benchmark 13: Vector Similarity ──────────────────────────
    let query_vec: Vec<f64> = (0..dims).map(|d| (d as f64 * 0.01).sin()).collect();
    let search_count = 100;
    let start = Instant::now();

    for _ in 0..search_count {
        vector.find_similar(&query_vec, 0.5, 10).unwrap();
    }

    let elapsed = start.elapsed();
    let ops = search_count as f64 / elapsed.as_secs_f64();
    println!(
        "  🎯 Similarity Search  │ {:>6} queries in {:>7.1}ms │ {:>12.0} ops/sec (top-10, {}D)",
        search_count, elapsed.as_secs_f64() * 1000.0, ops, dims
    );

    // ─── Benchmark 14: DriftQL Parse ──────────────────────────────
    let query_count = 1_000;
    let start = Instant::now();

    for _ in 0..query_count {
        let _stmt = driftdb_query::parse("FIND (u:User)-[:KNOWS]->(f:User) RETURN u.name, f.name").unwrap();
    }

    let elapsed = start.elapsed();
    let ops = query_count as f64 / elapsed.as_secs_f64();
    println!(
        "  📝 DriftQL Parse      │ {:>6} parses in {:>7.1}ms │ {:>12.0} ops/sec",
        query_count, elapsed.as_secs_f64() * 1000.0, ops
    );

    // ─── Benchmark 15: SHOW STATS ─────────────────────────────────
    let mut executor = Executor::new(graph.clone(), vector.clone());
    let stmt = driftdb_query::parse("SHOW STATS").unwrap();
    let start = Instant::now();
    let _ = executor.execute(stmt).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  📊 SHOW STATS         │      1 query  in {:>8.1}ms │ aggregation",
        elapsed.as_secs_f64() * 1000.0,
    );

    // ─── Summary ──────────────────────────────────────────────────
    let stats = storage.stats().unwrap();
    println!("\n  ════════════════════════════════════════════════");
    println!("  📈 Final: {}", stats);
    println!("  🦀 Powered by Rust + sled | LTO + O3 | Cached Trees | LRU\n");
}
