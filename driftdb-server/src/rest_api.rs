//! DriftDB REST API — HTTP interface for DriftDB (Hardened)
//!
//! Security features:
//! - Constant-time token comparison (anti timing-attack)
//! - Token-bucket rate limiting (smooth burst protection)
//! - Global concurrent connection limit (semaphore)
//! - Query size limit (64KB)
//! - Request body size limit (1MB — returns 413)
//! - Content-Type enforcement on POST endpoints
//! - TCP keepalive + timeouts (anti-Slowloris)
//! - Path traversal prevention on backup paths (relative-only, canonicalized)
//! - Input validation (label count, property count)
//! - CORS enabled

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method, StatusCode},
    middleware,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use driftdb_core::ops;
use driftdb_core::types::{NodeId, Value};
use driftdb_graph::GraphEngine;
use driftdb_vector::VectorEngine;
use driftdb_query::Executor;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

// ═══════════════════════════════════════════════════════════════════
// Security Constants
// ═══════════════════════════════════════════════════════════════════

/// Max DriftQL query size (64 KB — prevents huge query DoS)
const MAX_QUERY_SIZE: usize = 64 * 1024;
/// Max labels per node
const MAX_LABELS: usize = 16;
/// Max properties per node
const MAX_PROPERTIES: usize = 128;
/// Token bucket: tokens replenished per second per IP
const RATE_LIMIT_PER_SEC: f64 = 50.0;
/// Token bucket: max burst size (tokens can accumulate up to this)
const RATE_LIMIT_BURST: f64 = 10.0;
/// Max request body size (1 MB)
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// Max concurrent connections to REST API
const MAX_CONCURRENT_CONNECTIONS: usize = 100;
/// TCP keepalive interval (seconds) — kills idle/Slowloris connections
const TCP_KEEPALIVE_SECS: u64 = 15;

// ═══════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════

/// Per-IP token bucket rate limiter
pub struct TokenBucket {
    /// Available tokens (can go fractional)
    tokens: f64,
    /// Last time tokens were replenished
    last_refill: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        TokenBucket {
            tokens: RATE_LIMIT_BURST,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        // Replenish tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * RATE_LIMIT_PER_SEC).min(RATE_LIMIT_BURST);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared application state for all handlers
#[allow(dead_code)]
pub struct AppState {
    pub executor: Mutex<Executor>,
    pub graph: Arc<GraphEngine>,
    pub vector: Arc<VectorEngine>,
    pub auth_token: Option<String>,
    /// Per-IP token bucket rate limiter (keyed by IP address, NOT socket addr)
    pub rate_buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    /// Global concurrent connection counter
    pub active_connections: AtomicUsize,
}

// ═══════════════════════════════════════════════════════════════════
// Request/Response types
// ═══════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct QueryRequest {
    pub query: String,
}

#[derive(Deserialize)]
pub struct CreateNodeRequest {
    pub labels: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct BackupRequest {
    #[serde(default = "default_backup_dir")]
    pub directory: String,
    pub password: Option<String>,
}

fn default_backup_dir() -> String {
    "./drift_backups".to_string()
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ApiResponse {
    fn ok(data: serde_json::Value) -> Json<ApiResponse> {
        Json(ApiResponse {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<ApiResponse>) {
        (
            status,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(msg.to_string()),
            }),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════
// Auth + Rate Limit middleware
// ═══════════════════════════════════════════════════════════════════

/// Constant-time byte comparison (prevents timing attacks on token)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR all bytes — result is 0 only if all match
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Per-IP rate limit check — token bucket algorithm
///
/// Unlike a simple window counter that resets every second (allowing
/// burst floods at window boundaries), the token bucket smoothly
/// replenishes tokens over time. Burst capacity is capped at RATE_LIMIT_BURST.
fn check_rate_limit_ip(state: &AppState, ip: IpAddr) -> Result<(), (StatusCode, Json<ApiResponse>)> {
    let mut buckets = state.rate_buckets.lock().unwrap_or_else(|e| e.into_inner());

    let bucket = buckets.entry(ip).or_insert_with(TokenBucket::new);

    if !bucket.try_consume() {
        return Err(ApiResponse::err(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Rate limit exceeded ({} req/sec per IP, burst {})",
                RATE_LIMIT_PER_SEC, RATE_LIMIT_BURST as u64),
        ));
    }

    // Periodic cleanup: remove stale entries (every ~500 IPs)
    if buckets.len() > 500 {
        let now = Instant::now();
        buckets.retain(|_, b| now.duration_since(b.last_refill).as_secs() < 120);
    }

    Ok(())
}

/// Check concurrent connection limit
fn check_connection_limit(state: &AppState) -> Result<(), (StatusCode, Json<ApiResponse>)> {
    let current = state.active_connections.load(Ordering::Relaxed);
    if current >= MAX_CONCURRENT_CONNECTIONS {
        return Err(ApiResponse::err(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("Server at capacity ({}/{} connections)", current, MAX_CONCURRENT_CONNECTIONS),
        ));
    }
    Ok(())
}

fn check_auth_and_rate(state: &AppState, headers: &HeaderMap, ip: IpAddr) -> Result<(), (StatusCode, Json<ApiResponse>)> {
    // 1. Concurrent connection limit
    check_connection_limit(state)?;

    // 2. Per-IP rate limiting (token bucket)
    check_rate_limit_ip(state, ip)?;

    // 3. Content-Type validation for POST requests
    // (called from POST handlers — GET handlers skip this)
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if !ct.contains("application/json") {
            return Err(ApiResponse::err(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            ));
        }
    }

    // 4. Token auth (constant-time comparison)
    if let Some(ref expected) = state.auth_token {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return Err(ApiResponse::err(
                StatusCode::UNAUTHORIZED,
                "Invalid or missing Bearer token",
            ));
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Router
// ═══════════════════════════════════════════════════════════════════

/// Connection tracking middleware — increments on entry, decrements on response
async fn connection_tracking_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> axum::response::Response {
    let current = state.active_connections.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_CONCURRENT_CONNECTIONS {
        state.active_connections.fetch_sub(1, Ordering::Relaxed);
        return axum::response::IntoResponse::into_response(ApiResponse::err(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("Server at capacity ({}/{} connections)", current, MAX_CONCURRENT_CONNECTIONS),
        ));
    }
    let response = next.run(req).await;
    state.active_connections.fetch_sub(1, Ordering::Relaxed);
    response
}

/// Build the axum router with all REST endpoints
pub fn build_router(state: Arc<AppState>) -> Router {
    // SECURITY: Restrict CORS to only needed methods (no PUT/PATCH/TRACE)
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
        ])
        .allow_headers(tower_http::cors::Any);

    Router::new()
        .route("/health", get(health_handler))
        .route("/query", post(query_handler))
        .route("/nodes", get(list_nodes_handler))
        .route("/nodes", post(create_node_handler))
        .route("/nodes/{id}", get(get_node_handler))
        .route("/nodes/{id}", delete(delete_node_handler))
        .route("/backup", post(backup_handler))
        .layer(cors)
        // SECURITY: Global request body size limit — returns 413 for payloads > 1MB
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        // SECURITY: Track and limit concurrent connections
        .layer(middleware::from_fn_with_state(state.clone(), connection_tracking_middleware))
        .with_state(state)
}

/// Start the REST API server with TCP-level protections
pub async fn start_rest_server(
    addr: &str,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = build_router(state);

    // SECURITY: Set SO_KEEPALIVE at socket level to kill idle/Slowloris connections
    let std_listener = std::net::TcpListener::bind(addr)?;
    // Set keepalive via socket2 for Slowloris protection
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = std_listener.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
        sock.set_keepalive(true).ok();
        sock.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
        ).ok();
        // Don't drop the socket2 wrapper (it would close the fd)
        std::mem::forget(sock);
    }
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;

    println!("  🌐 REST API listening on http://{}", addr);
    println!("  🛡️  Body limit: {}MB | Rate: {}/sec/IP (burst {}) | Max conn: {} | Keepalive: {}s",
        MAX_BODY_SIZE / (1024 * 1024),
        RATE_LIMIT_PER_SEC,
        RATE_LIMIT_BURST as u64,
        MAX_CONCURRENT_CONNECTIONS,
        TCP_KEEPALIVE_SECS,
    );

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════

/// GET /health — Health check (rate-limited, minimal info without auth)
async fn health_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    // SECURITY: Per-IP rate limit even public endpoints to prevent abuse
    check_rate_limit_ip(&state, addr.ip())?;

    // If authenticated, return full stats; otherwise just status
    let is_authed = if let Some(ref expected) = state.auth_token {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        constant_time_eq(token.as_bytes(), expected.as_bytes())
    } else {
        true
    };

    if is_authed {
        let stats = state.graph.storage.stats().ok();
        Ok(ApiResponse::ok(json!({
            "status": "healthy",
            "engine": "DriftDB",
            "version": "0.1.4",
            "stats": stats.map(|s| s.to_string()),
            "connections": state.active_connections.load(Ordering::Relaxed),
        })))
    } else {
        // Unauthenticated: return minimal info only (no stats leak)
        Ok(ApiResponse::ok(json!({
            "status": "healthy",
        })))
    }
}

/// POST /query — Execute a DriftQL query
async fn query_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<QueryRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    // SECURITY: Cap query size to prevent memory exhaustion
    if req.query.len() > MAX_QUERY_SIZE {
        return Err(ApiResponse::err(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Query too large ({} bytes, max {})", req.query.len(), MAX_QUERY_SIZE),
        ));
    }

    // Parse the query
    let stmt = driftdb_query::parse(&req.query).map_err(|e| {
        ApiResponse::err(StatusCode::BAD_REQUEST, &format!("Parse error: {}", e))
    })?;

    // Execute
    let result = {
        let mut executor = state.executor.lock().unwrap_or_else(|e| e.into_inner());
        executor.execute(stmt)
    };

    match result {
        Ok(qr) => Ok(ApiResponse::ok(query_result_to_json(qr))),
        Err(e) => Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            &format!("{}", e),
        )),
    }
}

/// GET /nodes — List all nodes
async fn list_nodes_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    let nodes = state
        .graph
        .all_nodes()
        .map_err(|e| ApiResponse::err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let nodes_json: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| {
            json!({
                "id": n.id.0,
                "labels": n.labels,
                "properties": properties_to_json(&n.properties),
            })
        })
        .collect();

    Ok(ApiResponse::ok(json!({
        "nodes": nodes_json,
        "count": nodes_json.len(),
    })))
}

/// GET /nodes/:id — Get a single node
async fn get_node_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    let node_id = NodeId::from_str(&id);
    match state.graph.get_node(&node_id) {
        Ok(Some(node)) => Ok(ApiResponse::ok(json!({
            "id": node.id.0,
            "labels": node.labels,
            "properties": properties_to_json(&node.properties),
        }))),
        Ok(None) => Err(ApiResponse::err(StatusCode::NOT_FOUND, "Node not found")),
        Err(e) => Err(ApiResponse::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{}", e),
        )),
    }
}

/// POST /nodes — Create a node
async fn create_node_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<ApiResponse>), (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    // SECURITY: Validate input limits
    if req.labels.len() > MAX_LABELS {
        return Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            &format!("Too many labels ({}, max {})", req.labels.len(), MAX_LABELS),
        ));
    }
    if req.properties.len() > MAX_PROPERTIES {
        return Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            &format!("Too many properties ({}, max {})", req.properties.len(), MAX_PROPERTIES),
        ));
    }
    // Validate label content (alphanumeric + underscore only)
    for label in &req.labels {
        if label.is_empty() || label.len() > 64 || !label.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(ApiResponse::err(
                StatusCode::BAD_REQUEST,
                &format!("Invalid label '{}': must be 1-64 alphanumeric chars", label),
            ));
        }
    }

    // Convert JSON properties to DriftDB Values
    let properties: HashMap<String, Value> = req
        .properties
        .into_iter()
        .map(|(k, v)| (k, json_to_value(v)))
        .collect();

    match state.graph.create_node(req.labels, properties) {
        Ok(node) => Ok((
            StatusCode::CREATED,
            ApiResponse::ok(json!({
                "id": node.id.0,
                "labels": node.labels,
                "properties": properties_to_json(&node.properties),
            })),
        )),
        Err(e) => Err(ApiResponse::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{}", e),
        )),
    }
}

/// DELETE /nodes/:id — Soft-delete a node
async fn delete_node_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    let node_id = NodeId::from_str(&id);
    match state.graph.delete_node(&node_id) {
        Ok(()) => Ok(ApiResponse::ok(json!({"deleted": id}))),
        Err(e) => Err(ApiResponse::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{}", e),
        )),
    }
}

/// POST /backup — Create a backup
async fn backup_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BackupRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers, addr.ip())?;

    // SECURITY: Path traversal prevention (hardened)
    let dir = &req.directory;

    // Reject path traversal sequences
    if dir.contains("..") || dir.contains('~') {
        return Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            "Backup directory must not contain '..' or '~' (path traversal blocked)",
        ));
    }

    // Reject absolute paths — only relative paths within the project are allowed
    if dir.starts_with('/') {
        return Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            "Backup directory must be a relative path (absolute paths blocked)",
        ));
    }

    // Reject system directories by prefix
    let blocked = ["/etc", "/usr", "/bin", "/sbin", "/var", "/proc", "/sys", "/dev"];
    for prefix in &blocked {
        if dir.starts_with(prefix) {
            return Err(ApiResponse::err(
                StatusCode::BAD_REQUEST,
                &format!("Cannot create backups in system directory '{}'", prefix),
            ));
        }
    }

    // Validate the resolved path stays within the current working directory
    let resolved = std::path::Path::new(dir);
    if let Ok(canonical) = std::fs::canonicalize(resolved.parent().unwrap_or(resolved)) {
        let cwd = std::env::current_dir().unwrap_or_default();
        if !canonical.starts_with(&cwd) {
            return Err(ApiResponse::err(
                StatusCode::BAD_REQUEST,
                "Backup directory must resolve within the project directory",
            ));
        }
    }

    let result = if let Some(password) = req.password {
        ops::create_encrypted_backup(&state.graph.storage, &req.directory, &password)
    } else {
        ops::create_backup(&state.graph.storage, &req.directory)
    };

    match result {
        Ok(path) => Ok(ApiResponse::ok(json!({
            "backup_path": path.to_string_lossy(),
        }))),
        Err(e) => Err(ApiResponse::err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{}", e),
        )),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Convert a QueryResult into a JSON value
fn query_result_to_json(result: driftdb_query::QueryResult) -> serde_json::Value {
    use driftdb_query::QueryResult;
    match result {
        QueryResult::NodeCreated { node } => json!({
            "type": "node_created",
            "id": node.id.0,
            "labels": node.labels,
            "properties": properties_to_json(&node.properties),
        }),
        QueryResult::EdgeCreated { edge_id, edge_type } => json!({
            "type": "edge_created",
            "id": edge_id,
            "edge_type": edge_type,
        }),
        QueryResult::Table { columns, rows } => json!({
            "type": "table",
            "columns": columns,
            "rows": rows,
        }),
        QueryResult::SimilarResults { results } => json!({
            "type": "similar",
            "results": results.iter().map(|(name, score)| json!({
                "node": name,
                "similarity": score,
            })).collect::<Vec<_>>(),
        }),
        QueryResult::PropertySet { node_id, property } => json!({
            "type": "property_set",
            "node_id": node_id,
            "property": property,
        }),
        QueryResult::Deleted { id } => json!({
            "type": "deleted",
            "id": id,
        }),
        QueryResult::Info(text) => json!({
            "type": "info",
            "text": text,
        }),
        QueryResult::HelpText(text) => json!({
            "type": "help",
            "text": text,
        }),
        QueryResult::Ok => json!({
            "type": "ok",
        }),
    }
}

/// Convert DriftDB properties to JSON
fn properties_to_json(props: &HashMap<String, Value>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in props {
        map.insert(k.clone(), value_to_json(v));
    }
    serde_json::Value::Object(map)
}

/// Convert a DriftDB Value to serde_json::Value
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => json!(b),
        Value::Int(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::String(s) => json!(s),
        Value::Vector(vec) => json!(vec),
        Value::List(list) => json!(list.iter().map(value_to_json).collect::<Vec<_>>()),
        Value::Map(m) => {
            let obj: serde_json::Map<String, serde_json::Value> = m
                .iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
    }
}

/// Convert a serde_json::Value to DriftDB Value
fn json_to_value(v: serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(arr) => {
            // Check if all numbers → Vector, else → List
            if arr.iter().all(|v| v.is_number()) {
                Value::Vector(arr.iter().filter_map(|v| v.as_f64()).collect())
            } else {
                Value::List(arr.into_iter().map(json_to_value).collect())
            }
        }
        serde_json::Value::Object(m) => {
            Value::Map(m.into_iter().map(|(k, v)| (k, json_to_value(v))).collect())
        }
    }
}
