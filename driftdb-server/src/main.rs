//! DriftDB — A next-generation database
//!
//! Binary entry point. Handles CLI args and launches the REPL or WebSocket server.

// AMD Zen optimization: jemalloc's thread-local arenas align with
// AMD's CCX topology — eliminates cross-CCD malloc contention
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod repl;
mod rest_api;
mod ws_server;

use clap::Parser;
use colored::*;
use driftdb_core::sync::SyncEngine;
use driftdb_core::Storage;
use driftdb_graph::GraphEngine;
use driftdb_query::Executor;
use driftdb_vector::VectorEngine;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "driftdb",
    about = "DriftDB — A next-generation database. Graph-native, time-aware, vector-capable, security-hardened.",
    version = "0.1.0"
)]
struct Cli {
    /// Path to the database directory
    #[arg(short, long, default_value = "./drift_data")]
    data_dir: String,

    /// Run in memory-only mode (no persistence)
    #[arg(long)]
    memory: bool,

    /// Require password authentication
    #[arg(long)]
    auth: bool,

    /// Start the WebSocket real-time sync server
    #[arg(long)]
    serve: bool,

    /// WebSocket server port (default: 9210)
    #[arg(long, default_value = "9210")]
    port: u16,

    /// Bind address for WebSocket server (default: 127.0.0.1 = localhost only)
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Authentication token for WebSocket clients (required if set)
    #[arg(long)]
    ws_token: Option<String>,

    /// Authentication token for REST API (defaults to --ws-token if not set)
    #[arg(long)]
    rest_token: Option<String>,

    /// Enable REST API server
    #[arg(long)]
    rest: bool,

    /// REST API port (default: 9211)
    #[arg(long, default_value = "9211")]
    rest_port: u16,

    /// TLS certificate file (PEM format) for wss://
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key file (PEM format) for wss://
    #[arg(long)]
    tls_key: Option<String>,

    /// Execute a single query and exit
    #[arg(short, long)]
    execute: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Initialize storage
    let storage = if cli.memory {
        println!(
            "  {} {}",
            "ℹ".bright_blue(),
            "Running in memory-only mode".dimmed()
        );
        Storage::temporary().expect("Failed to create in-memory database")
    } else {
        println!(
            "  {} Data directory: {}",
            "ℹ".bright_blue(),
            cli.data_dir.bright_white()
        );
        Storage::open(&cli.data_dir).expect("Failed to open database")
    };

    let storage = Arc::new(storage);
    let graph = Arc::new(GraphEngine::new(storage.clone()));
    let vector = Arc::new(VectorEngine::new(storage.clone()));

    // Create the real-time sync engine and wire it to the event bus
    let sync_engine = Arc::new(SyncEngine::new());

    // Connect the sync engine to the storage event bus
    // Every mutation in DriftDB will auto-broadcast to subscribers
    {
        let sync = sync_engine.clone();
        storage.events.subscribe(Box::new(move |event| {
            sync.broadcast(event);
        }));
    }

    if let Some(query) = cli.execute {
        // Single query mode
        let mut executor = Executor::new(graph, vector);
        let stmt = driftdb_query::parse(&query).unwrap_or_else(|e| {
            eprintln!("{} {}", "Error:".red(), e);
            std::process::exit(1);
        });
        match executor.execute(stmt) {
            Ok(result) => {
                println!("{:?}", result);
            }
            Err(e) => {
                eprintln!("{} {}", "Error:".red(), e);
                std::process::exit(1);
            }
        }
    } else if cli.serve {
        // Server mode — run WS server + optional REST API + REPL
        let ws_addr = format!("{}:{}", cli.bind, cli.port);
        let executor = Executor::new(graph.clone(), vector.clone());

        // Security warning if binding to all interfaces
        if cli.bind == "0.0.0.0" {
            println!(
                "  {} {}",
                "⚠".bright_yellow(),
                "WARNING: Binding to 0.0.0.0 exposes the database to the network!".bright_red()
            );
            if cli.ws_token.is_none() {
                println!(
                    "  {} {}",
                    "⚠".bright_yellow(),
                    "CRITICAL: No --ws-token set! Anyone can connect!".bright_red()
                );
            }
        }

        // Run WS server in background thread
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let sync_clone = sync_engine.clone();
        let ws_token_clone = cli.ws_token.clone();
        let ws_addr_clone = ws_addr.clone();
        let cli_tls_cert = cli.tls_cert.clone();
        let cli_tls_key = cli.tls_key.clone();
        std::thread::spawn(move || {
            rt.block_on(async {
                let mut server = ws_server::SyncServer::new(sync_clone);
                if let Some(token) = ws_token_clone {
                    server = server.with_auth(token);
                }
                if let Some(cert) = cli_tls_cert {
                    if let Some(key) = cli_tls_key {
                        server = server.with_tls(cert, key);
                    }
                }
                if let Err(e) = server.start(&ws_addr_clone).await {
                    eprintln!("  {} WebSocket server error: {}", "✗".red(), e);
                }
            });
        });

        println!(
            "  {} WebSocket sync: {}",
            "🔌".to_string(),
            format!("ws://localhost:{}", cli.port).bright_green()
        );

        // Run REST API server in background thread (if --rest)
        if cli.rest {
            // SECURITY: REST token defaults to ws_token if not explicitly set
            let rest_auth_token = cli.rest_token.clone().or_else(|| cli.ws_token.clone());

            if rest_auth_token.is_none() {
                println!(
                    "  {} {}",
                    "⚠".bright_yellow(),
                    "WARNING: REST API has no auth token! Set --rest-token or --ws-token".bright_red()
                );
            }

            let rest_addr = format!("{}:{}", cli.bind, cli.rest_port);
            let rest_state = Arc::new(rest_api::AppState {
                executor: std::sync::Mutex::new(Executor::new(graph.clone(), vector.clone())),
                graph: graph.clone(),
                vector: vector.clone(),
                auth_token: rest_auth_token,
                request_count: std::sync::atomic::AtomicU64::new(0),
                rate_window_start: std::sync::Mutex::new(std::time::Instant::now()),
            });
            let rest_addr_clone = rest_addr.clone();
            std::thread::spawn(move || {
                let rt2 = tokio::runtime::Runtime::new().expect("Failed to create REST runtime");
                rt2.block_on(async {
                    if let Err(e) = rest_api::start_rest_server(&rest_addr_clone, rest_state).await {
                        eprintln!("  {} REST API error: {}", "✗".red(), e);
                    }
                });
            });
            println!(
                "  {} REST API:       {}",
                "🌐".to_string(),
                format!("http://localhost:{}", cli.rest_port).bright_green()
            );
        }
        println!();

        // Run REPL in the main thread
        let mut repl = repl::Repl::new(executor, storage, cli.auth);
        repl.run();
    } else {
        // Interactive REPL mode (no WebSocket)
        let executor = Executor::new(graph, vector);
        let mut repl = repl::Repl::new(executor, storage, cli.auth);
        repl.run();
    }
}
