//! DriftDB — WebSocket Real-Time Sync Server (Hardened)
//!
//! Security features:
//! - Token-based authentication on connect
//! - Connection limits (max_connections)
//! - Message size limits (16KB max)
//! - Rate limiting (100 msg/sec per client)
//! - Localhost-only binding by default
//! - Graceful error handling (no panics)
//! - Auto-cleanup on disconnect

use driftdb_core::sync::{
    ChangeCallback, ChangeEvent, ClientMessage, ServerMessage, SyncEngine,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

// ═══════════════════════════════════════════════════════════════════
// Security Constants
// ═══════════════════════════════════════════════════════════════════

/// Maximum WebSocket message size (16 KB)
const MAX_MESSAGE_SIZE: usize = 16 * 1024;
/// Maximum connections allowed
const MAX_CONNECTIONS: usize = 64;
/// Maximum messages per second per client (rate limit)
const RATE_LIMIT_PER_SEC: u32 = 100;
/// Maximum subscriptions per client
const MAX_SUBS_PER_CLIENT: usize = 50;

// ═══════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════

/// Hardened WebSocket sync server (optional TLS)
pub struct SyncServer {
    pub sync_engine: Arc<SyncEngine>,
    clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<String>>>>,
    connection_count: Arc<AtomicUsize>,
    /// Optional auth token — if set, clients must send it on first message
    auth_token: Option<String>,
    /// Optional TLS config (cert + key paths)
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

impl SyncServer {
    pub fn new(sync_engine: Arc<SyncEngine>) -> Self {
        SyncServer {
            sync_engine,
            clients: Arc::new(Mutex::new(HashMap::new())),
            connection_count: Arc::new(AtomicUsize::new(0)),
            auth_token: None,
            tls_cert: None,
            tls_key: None,
        }
    }

    /// Set an authentication token. Clients must send {"type":"auth","token":"..."} first.
    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }

    /// Enable TLS with cert and key PEM file paths
    pub fn with_tls(mut self, cert_path: String, key_path: String) -> Self {
        self.tls_cert = Some(cert_path);
        self.tls_key = Some(key_path);
        self
    }

    /// Start the WebSocket server on the given address (plain or TLS)
    pub async fn start(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;

        // Load TLS config if cert/key provided
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&self.tls_cert, &self.tls_key) {
            let cert_file = std::fs::File::open(cert_path)
                .map_err(|e| format!("Cannot open TLS cert '{}': {}", cert_path, e))?;
            let key_file = std::fs::File::open(key_path)
                .map_err(|e| format!("Cannot open TLS key '{}': {}", key_path, e))?;

            let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                .filter_map(|r| r.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
                .map_err(|e| format!("Invalid TLS key: {}", e))?
                .ok_or("No private key found in key file")?;

            let config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| format!("TLS config error: {}", e))?;

            println!("  🔐 TLS ENABLED — wss://{}", addr);
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
        } else {
            None
        };

        let scheme = if tls_acceptor.is_some() { "wss" } else { "ws" };
        println!("  🔌 WebSocket sync server listening on {}://{}", scheme, addr);
        println!("  🛡️  Security: max_conn={}, rate_limit={}/s, max_msg={}KB, max_subs={}",
            MAX_CONNECTIONS, RATE_LIMIT_PER_SEC, MAX_MESSAGE_SIZE / 1024, MAX_SUBS_PER_CLIENT
        );
        if self.auth_token.is_some() {
            println!("  🔒 Token authentication ENABLED");
        }
        println!("  📡 Clients can subscribe to real-time changes\n");

        loop {
            let (stream, peer_addr) = listener.accept().await?;

            // Check connection limit BEFORE accepting
            let current = self.connection_count.load(Ordering::Relaxed);
            if current >= MAX_CONNECTIONS {
                eprintln!(
                    "  ⚠ Connection rejected from {} (limit {}/{})",
                    peer_addr, current, MAX_CONNECTIONS
                );
                drop(stream);
                continue;
            }

            let sync_engine = self.sync_engine.clone();
            let clients = self.clients.clone();
            let conn_count = self.connection_count.clone();
            let auth_token = self.auth_token.clone();
            let tls = tls_acceptor.clone();

            tokio::spawn(async move {
                conn_count.fetch_add(1, Ordering::Relaxed);

                let result = if let Some(acceptor) = tls {
                    // TLS connection: TCP → TLS → WebSocket
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_tls_connection(tls_stream, peer_addr, sync_engine, clients.clone(), auth_token).await
                        }
                        Err(e) => {
                            eprintln!("  ✗ TLS handshake failed for {}: {}", peer_addr, e);
                            Ok(())
                        }
                    }
                } else {
                    // Plain connection: TCP → WebSocket
                    handle_connection(stream, peer_addr, sync_engine, clients.clone(), auth_token).await
                };

                if let Err(e) = result {
                    eprintln!("  ✗ Client {} error: {}", peer_addr, e);
                }

                conn_count.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Get number of connected clients
    #[allow(dead_code)]
    pub fn client_count(&self) -> usize {
        self.connection_count.load(Ordering::Relaxed)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Rate Limiter
// ═══════════════════════════════════════════════════════════════════

struct RateLimiter {
    count: u32,
    window_start: Instant,
    max_per_sec: u32,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> Self {
        RateLimiter {
            count: 0,
            window_start: Instant::now(),
            max_per_sec,
        }
    }

    /// Returns true if the request should be allowed
    fn check(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs_f64();

        if elapsed >= 1.0 {
            // Reset window
            self.count = 0;
            self.window_start = now;
        }

        self.count += 1;
        self.count <= self.max_per_sec
    }
}

// ═══════════════════════════════════════════════════════════════════
// Connection Handler
// ═══════════════════════════════════════════════════════════════════

/// Handle a TLS-wrapped WebSocket connection
async fn handle_tls_connection(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    sync_engine: Arc<SyncEngine>,
    clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<String>>>>,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    handle_ws_stream(ws_stream, peer_addr, sync_engine, clients, auth_token).await
}

/// Handle a plain TCP WebSocket connection
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    sync_engine: Arc<SyncEngine>,
    clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<String>>>>,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    handle_ws_stream(ws_stream, peer_addr, sync_engine, clients, auth_token).await
}

/// Common WebSocket handler for both plain and TLS connections
async fn handle_ws_stream<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    peer_addr: SocketAddr,
    sync_engine: Arc<SyncEngine>,
    clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<String>>>>,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // SECURITY: Bounded channel prevents memory leak from slow/stopped readers.
    // An AI could subscribe to All then stop reading — unbounded = OOM.
    // When full, new messages are dropped (backpressure).
    const MAX_BUFFERED_MESSAGES: usize = 1024;
    let (tx, mut rx) = mpsc::channel::<String>(MAX_BUFFERED_MESSAGES);

    // Add to client map
    if let Ok(mut clients_map) = clients.lock() {
        clients_map.insert(peer_addr, tx.clone());
        println!(
            "  ✓ Client connected: {} ({} total)",
            peer_addr,
            clients_map.len()
        );
    }

    // Track subscriptions per client (with limit)
    let client_subs: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let mut rate_limiter = RateLimiter::new(RATE_LIMIT_PER_SEC);
    let mut authenticated = auth_token.is_none(); // If no token set, auto-authed
    let mut auth_failures: u32 = 0;
    const MAX_AUTH_FAILURES: u32 = 3;

    // Forward task
    let forward_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages
    while let Some(msg) = ws_receiver.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(_) => break,
        };

        if msg.is_close() {
            break;
        }

        if let Message::Text(text) = msg {
            let text_str: &str = text.as_ref();

            // ── Security Check 1: Message size limit ──────────────
            if text_str.len() > MAX_MESSAGE_SIZE {
                let err = ServerMessage::Error {
                    message: format!(
                        "Message too large ({} bytes, max {})",
                        text_str.len(),
                        MAX_MESSAGE_SIZE
                    ),
                };
                let json = serde_json::to_string(&err).unwrap_or_default();
                let _ = tx.try_send(json);
                continue;
            }

            // ── Security Check 2: Rate limiting ───────────────────
            if !rate_limiter.check() {
                let err = ServerMessage::Error {
                    message: format!(
                        "Rate limit exceeded ({} msg/sec max)",
                        RATE_LIMIT_PER_SEC
                    ),
                };
                let json = serde_json::to_string(&err).unwrap_or_default();
                let _ = tx.try_send(json);
                continue;
            }

            // ── Security Check 3: Authentication ──────────────────
            if !authenticated {
                // Brute-force lockout: 3 failures = disconnect
                if auth_failures >= MAX_AUTH_FAILURES {
                    let err = ServerMessage::Error {
                        message: "Too many failed auth attempts. Disconnected.".into(),
                    };
                    let json = serde_json::to_string(&err).unwrap_or_default();
                    let _ = tx.try_send(json);
                    break; // Kill the connection
                }

                // Expect auth message first
                let mut auth_ok = false;
                if let Ok(auth_msg) = serde_json::from_str::<serde_json::Value>(text_str) {
                    if auth_msg.get("type").and_then(|t| t.as_str()) == Some("auth") {
                        if let Some(token) = auth_msg.get("token").and_then(|t| t.as_str()) {
                            // CONSTANT-TIME comparison to prevent timing attacks
                            // An attacker measuring response time per-byte could
                            // brute force the token if we used ==
                            if let Some(ref expected) = auth_token {
                                auth_ok = constant_time_eq(token.as_bytes(), expected.as_bytes());
                            }
                        }
                    }
                }

                if auth_ok {
                    authenticated = true;
                    auth_failures = 0;
                    let ok = ServerMessage::Subscribed { sub_id: 0 };
                    let json = serde_json::to_string(&ok).unwrap_or_default();
                    let _ = tx.try_send(json);
                    continue;
                }

                auth_failures += 1;
                let err = ServerMessage::Error {
                    message: format!(
                        "Authentication failed ({}/{} attempts). Send {{\"type\":\"auth\",\"token\":\"...\"}}",
                        auth_failures, MAX_AUTH_FAILURES
                    ),
                };
                let json = serde_json::to_string(&err).unwrap_or_default();
                let _ = tx.try_send(json);
                continue;
            }

            // ── Parse and handle message ──────────────────────────
            match serde_json::from_str::<ClientMessage>(text_str) {
                Ok(client_msg) => {
                    let response = handle_client_message(
                        client_msg,
                        &sync_engine,
                        &tx,
                        &client_subs,
                    );

                    if let Some(resp) = response {
                        let json = serde_json::to_string(&resp).unwrap_or_default();
                        let _ = tx.try_send(json);
                    }
                }
                Err(e) => {
                    let err = ServerMessage::Error {
                        message: format!("Invalid message: {}", e),
                    };
                    let json = serde_json::to_string(&err).unwrap_or_default();
                    let _ = tx.try_send(json);
                }
            }
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────
    if let Ok(subs) = client_subs.lock() {
        for sub_id in subs.iter() {
            sync_engine.unsubscribe(*sub_id);
        }
    }

    if let Ok(mut clients_map) = clients.lock() {
        clients_map.remove(&peer_addr);
        println!(
            "  ✗ Client disconnected: {} ({} remaining)",
            peer_addr,
            clients_map.len()
        );
    }

    forward_task.abort();
    Ok(())
}

/// Process a single client message — with subscription limit
fn handle_client_message(
    msg: ClientMessage,
    sync_engine: &Arc<SyncEngine>,
    tx: &mpsc::Sender<String>,
    client_subs: &Arc<Mutex<Vec<u64>>>,
) -> Option<ServerMessage> {
    match msg {
        ClientMessage::Subscribe { filter } => {
            // SECURITY: Validate filter to prevent stack overflow from
            // deeply nested Any(Any(Any(...))) and oversized strings
            if let Err(e) = filter.validate() {
                return Some(ServerMessage::Error {
                    message: format!("Invalid filter: {}", e),
                });
            }

            // Check subscription limit per client
            if let Ok(subs) = client_subs.lock() {
                if subs.len() >= MAX_SUBS_PER_CLIENT {
                    return Some(ServerMessage::Error {
                        message: format!(
                            "Subscription limit reached ({} max per client)",
                            MAX_SUBS_PER_CLIENT
                        ),
                    });
                }
            }

            let tx_clone = tx.clone();
            let callback: ChangeCallback = Box::new(move |change: ChangeEvent| {
                let msg = ServerMessage::Change {
                    sub_id: change.sub_id,
                    event_type: change.event_type,
                    data: change.data,
                    seq: change.seq,
                };
                let json = serde_json::to_string(&msg).unwrap_or_default();
                let _ = tx_clone.try_send(json);
            });

            let sub_id = sync_engine.subscribe(filter, callback);
            if let Ok(mut subs) = client_subs.lock() {
                subs.push(sub_id);
            }

            Some(ServerMessage::Subscribed { sub_id })
        }

        ClientMessage::Unsubscribe { sub_id } => {
            sync_engine.unsubscribe(sub_id);
            if let Ok(mut subs) = client_subs.lock() {
                subs.retain(|&id| id != sub_id);
            }
            Some(ServerMessage::Unsubscribed { sub_id })
        }

        ClientMessage::Ping => Some(ServerMessage::Pong {
            connections: sync_engine.subscription_count(),
        }),

        ClientMessage::Query { sql: _ } => Some(ServerMessage::Error {
            message: "Query execution over WebSocket not yet wired".into(),
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Crypto utilities
// ═══════════════════════════════════════════════════════════════════

/// Constant-time byte comparison — prevents timing side-channel attacks.
///
/// A naive `==` on strings will short-circuit on the first mismatched byte.
/// An attacker can measure response time to learn how many bytes matched,
/// brute-forcing the token character by character.
///
/// This function XORs every byte and only checks the result at the end,
/// so it always takes the same time regardless of where the mismatch is.
#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still do work to avoid leaking length via timing
        let mut _dummy: u8 = 0;
        for byte in a.iter().chain(b.iter()) {
            _dummy ^= byte;
        }
        return false;
    }

    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
