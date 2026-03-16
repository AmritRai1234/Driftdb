//! DriftDB REST API — HTTP interface for DriftDB (Hardened)
//!
//! Security features:
//! - Constant-time token comparison (anti timing-attack)
//! - Rate limiting (100 req/sec global cap)
//! - Query size limit (64KB)
//! - Path traversal prevention on backup paths
//! - Input validation (label count, property count)
//! - CORS enabled

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};

// ═══════════════════════════════════════════════════════════════════
// Security Constants
// ═══════════════════════════════════════════════════════════════════

/// Max DriftQL query size (64 KB — prevents huge query DoS)
const MAX_QUERY_SIZE: usize = 64 * 1024;
/// Max labels per node
const MAX_LABELS: usize = 16;
/// Max properties per node
const MAX_PROPERTIES: usize = 128;
/// Rate limit: max requests per second
const RATE_LIMIT_PER_SEC: u64 = 100;

// ═══════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════

/// Shared application state for all handlers
#[allow(dead_code)]
pub struct AppState {
    pub executor: Mutex<Executor>,
    pub graph: Arc<GraphEngine>,
    pub vector: Arc<VectorEngine>,
    pub auth_token: Option<String>,
    /// Rate limiter state
    pub request_count: AtomicU64,
    pub rate_window_start: Mutex<Instant>,
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

fn check_auth_and_rate(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<ApiResponse>)> {
    // 1. Rate limiting
    {
        let mut window = state.rate_window_start.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if now.duration_since(*window).as_secs() >= 1 {
            // New window
            state.request_count.store(1, Ordering::Relaxed);
            *window = now;
        } else {
            let count = state.request_count.fetch_add(1, Ordering::Relaxed);
            if count >= RATE_LIMIT_PER_SEC {
                return Err(ApiResponse::err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded (100 req/sec)",
                ));
            }
        }
    }

    // 2. Token auth (constant-time comparison)
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

/// Build the axum router with all REST endpoints
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_handler))
        .route("/query", post(query_handler))
        .route("/nodes", get(list_nodes_handler))
        .route("/nodes", post(create_node_handler))
        .route("/nodes/{id}", get(get_node_handler))
        .route("/nodes/{id}", delete(delete_node_handler))
        .route("/backup", post(backup_handler))
        .layer(cors)
        .with_state(state)
}

/// Start the REST API server
pub async fn start_rest_server(
    addr: &str,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("  🌐 REST API listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════

/// GET /health — Health check + database stats
async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse> {
    let stats = state.graph.storage.stats().ok();
    ApiResponse::ok(json!({
        "status": "healthy",
        "engine": "DriftDB",
        "version": "0.1.0",
        "stats": stats.map(|s| s.to_string()),
    }))
}

/// POST /query — Execute a DriftQL query
async fn query_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<QueryRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

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
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("{}", e),
        )),
    }
}

/// GET /nodes — List all nodes
async fn list_nodes_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

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
    headers: HeaderMap,
    Json(req): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<ApiResponse>), (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

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
    headers: HeaderMap,
    Json(req): Json<BackupRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    check_auth_and_rate(&state, &headers)?;

    // SECURITY: Path traversal prevention
    let dir = &req.directory;
    if dir.contains("..") || dir.contains('~') {
        return Err(ApiResponse::err(
            StatusCode::BAD_REQUEST,
            "Backup directory must not contain '..' or '~' (path traversal blocked)",
        ));
    }
    let blocked = ["/etc", "/usr", "/bin", "/sbin", "/var", "/proc", "/sys", "/dev"];
    for prefix in &blocked {
        if dir.starts_with(prefix) {
            return Err(ApiResponse::err(
                StatusCode::BAD_REQUEST,
                &format!("Cannot create backups in system directory '{}'", prefix),
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
