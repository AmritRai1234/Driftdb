# DriftDB Documentation

> **DriftDB** — A next-generation database. Graph-native, time-aware, vector-capable.
>
> Built in Rust. AMD-optimized. Security-hardened.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [DriftQL Reference](#driftql-reference)
3. [CLI Usage](#cli-usage)
4. [REST API](#rest-api)
5. [Python SDK](#python-sdk)
6. [Architecture](#architecture)

---

## Quick Start

### Install & Run

```bash
# Build from source
cargo build --release

# Start REPL
./target/release/driftdb

# Start with WebSocket + REST API
./target/release/driftdb --serve --rest --ws-token my-secret-token

# Start with TLS
./target/release/driftdb --serve --rest --tls-cert cert.pem --tls-key key.pem
```

### First Commands

```sql
-- Create nodes
CREATE (u:User {name: "Amrit", age: 25})
CREATE (p:Project {name: "DriftDB", language: "Rust"})

-- Create a relationship
LINK (u)-[:BUILT]->(p)

-- Query
FIND (u:User) RETURN u.name, u.age

-- Stats
SHOW STATS
```

---

## DriftQL Reference

DriftQL is a query language inspired by Cypher (Neo4j) but designed specifically for DriftDB.

### CREATE — Create Nodes

```sql
-- Basic node
CREATE (Person {name: "Alice"})

-- With variable binding (for use in same session)
CREATE (u:User {name: "Amrit", age: 25, active: true})

-- Multiple labels
CREATE (a:User:Admin {name: "Root", level: 10})

-- Supported value types
CREATE (n:Test {
    str: "hello",
    num: 42,
    float: 3.14,
    flag: true,
    empty: null,
    vec: [0.1, 0.2, 0.3]
})
```

**Syntax:** `CREATE (variable:Label {key: value, ...})`

| Part | Required | Description |
|---|---|---|
| `variable` | Optional | Session variable name (e.g., `u`) |
| `:Label` | Optional | One or more labels separated by `:` |
| `{...}` | Optional | Key-value property map |

---

### LINK — Create Edges (Relationships)

```sql
-- Basic edge
LINK (u)-[:FOLLOWS]->(v)

-- With properties
LINK (u)-[:RATED {score: 9.5, date: "2025-01-01"}]->(movie)

-- Using label lookup (if no variable is bound)
LINK (u:User {name: "Amrit"})-[:BUILT]->(p:Project {name: "DriftDB"})
```

**Syntax:** `LINK (source)-[:EDGE_TYPE {props}]->(target)`

| Part | Required | Description |
|---|---|---|
| `(source)` | Yes | Source node ref (variable, ID, or label+conditions) |
| `[:TYPE]` | Yes | Edge type (uppercase by convention) |
| `{...}` | Optional | Edge properties |
| `(target)` | Yes | Target node ref |

---

### FIND — Query Nodes & Patterns

#### Simple node query

```sql
-- Find all User nodes
FIND (u:User) RETURN u.name

-- Find all nodes (no label filter)
FIND (n)
```

#### Pattern matching (relationships)

```sql
-- Find users who BUILT projects
FIND (u:User)-[:BUILT]->(p:Project) RETURN u.name, p.name

-- Multi-hop patterns
FIND (a:User)-[:FOLLOWS]->(b:User)-[:LIKES]->(s:Song) RETURN a.name, s.title
```

#### WHERE clause (filtering)

```sql
-- Numeric comparison
FIND (u:User) WHERE u.age > 18 RETURN u.name

-- Equality
FIND (u:User) WHERE u.name = "Amrit" RETURN u

-- Multiple conditions (AND)
FIND (u:User) WHERE u.age >= 18 AND u.active = true RETURN u.name
```

**Comparison operators:** `=`, `!=`, `<`, `>`, `<=`, `>=`

#### Time-travel queries

```sql
-- Query state at a specific timestamp
FIND (u:User) AT "2025-01-01T00:00:00Z" RETURN u.name
```

---

### FIND SIMILAR — Vector Similarity Search

```sql
-- Find vectors similar to a query vector
FIND SIMILAR TO [0.1, 0.5, 0.9, 0.3] WITHIN 0.8

-- With result limit
FIND SIMILAR TO [0.1, 0.5, 0.9] WITHIN 0.5 LIMIT 5

-- With return fields
FIND SIMILAR TO [0.1, 0.2, 0.3] WITHIN 0.7 LIMIT 10 RETURN n.name
```

**Syntax:** `FIND SIMILAR TO [vector] WITHIN threshold LIMIT n`

| Part | Required | Description |
|---|---|---|
| `[vector]` | Yes | Query vector as array of floats |
| `WITHIN` | Optional | Minimum cosine similarity threshold (0.0–1.0) |
| `LIMIT` | Optional | Max number of results (default: 10) |

---

### SET — Update Properties

```sql
-- Update a property
SET u.name = "New Name"

-- Set a numeric property
SET u.age = 26

-- Set a boolean
SET u.verified = true
```

**Syntax:** `SET variable.property = value`

> **Note:** The variable must have been bound in the current REPL session via `CREATE (var:Label {...})`.

---

### DELETE — Remove Nodes

```sql
-- Soft-delete a node by variable
DELETE (u)

-- Delete by label + condition
DELETE (u:User {name: "old_user"})
```

**Syntax:** `DELETE (node_ref)`

---

### SHOW — Database Inspection

```sql
SHOW NODES     -- List all nodes with IDs, labels, and properties
SHOW EDGES     -- List all edges with source, target, and type
SHOW STATS     -- Database statistics (counts, disk size)
SHOW EVENTS    -- Recent event log (last 20 events)
```

---

### HELP — Quick Reference

```sql
HELP           -- Print inline syntax reference
```

---

### Comments

```sql
-- This is a line comment (ignored by the parser)
CREATE (u:User {name: "Amrit"})  -- Inline comment
```

---

### Value Types

| Type | Examples | Description |
|---|---|---|
| String | `"hello"`, `'world'` | Double or single quoted |
| Integer | `42`, `-7`, `0` | 64-bit signed integer |
| Float | `3.14`, `0.5` | 64-bit floating point |
| Boolean | `true`, `false` | Case-insensitive |
| Null | `null` | Null/empty value |
| Vector | `[0.1, 0.2, 0.3]` | Array of floats (for similarity search) |
| List | `["a", 1, true]` | Mixed-type array |

---

## CLI Usage

```
driftdb [OPTIONS]

OPTIONS:
    -d, --data-dir <PATH>     Database directory (default: ./drift_data)
        --memory              Run in memory-only mode (no persistence)
        --auth                Require password authentication for REPL
        --serve               Start WebSocket real-time sync server
        --port <PORT>         WebSocket server port (default: 9210)
        --bind <ADDR>         Bind address (default: 127.0.0.1)
        --ws-token <TOKEN>    Auth token for WebSocket/REST clients
        --rest                Enable REST API server
        --rest-port <PORT>    REST API port (default: 9211)
        --tls-cert <FILE>     TLS certificate PEM file (enables wss://)
        --tls-key <FILE>      TLS private key PEM file
    -e, --execute <QUERY>     Execute a single query and exit
    -h, --help                Print help
    -V, --version             Print version
```

### Examples

```bash
# Interactive REPL
driftdb

# In-memory mode
driftdb --memory

# Full server (WS + REST + REPL)
driftdb --serve --rest --ws-token secret123

# Execute a query and exit
driftdb -e 'SHOW STATS'

# Production deployment with TLS
driftdb --serve --rest --bind 0.0.0.0 --ws-token $(openssl rand -hex 32) \
        --tls-cert /etc/ssl/driftdb.crt --tls-key /etc/ssl/driftdb.key
```

---

## REST API

Base URL: `http://localhost:9211` (when started with `--rest`)

### Authentication

All endpoints (except `/health`) require Bearer token when `--ws-token` is set:

```
Authorization: Bearer your-token-here
```

### Endpoints

#### GET /health

```bash
curl http://localhost:9211/health
```

```json
{"success": true, "data": {"status": "healthy", "engine": "DriftDB", "version": "0.1.0"}}
```

#### POST /query — Execute DriftQL

```bash
curl -X POST http://localhost:9211/query \
  -H "Authorization: Bearer secret" \
  -H "Content-Type: application/json" \
  -d '{"query": "FIND (u:User) RETURN u.name"}'
```

```json
{"success": true, "data": {"type": "table", "columns": ["u.name"], "rows": [["Amrit"]]}}
```

#### POST /nodes — Create Node

```bash
curl -X POST http://localhost:9211/nodes \
  -H "Authorization: Bearer secret" \
  -H "Content-Type: application/json" \
  -d '{"labels": ["User"], "properties": {"name": "Amrit", "age": 25}}'
```

#### GET /nodes — List All Nodes

```bash
curl -H "Authorization: Bearer secret" http://localhost:9211/nodes
```

#### GET /nodes/:id — Get Node

```bash
curl -H "Authorization: Bearer secret" http://localhost:9211/nodes/abc123
```

#### DELETE /nodes/:id — Delete Node

```bash
curl -X DELETE -H "Authorization: Bearer secret" http://localhost:9211/nodes/abc123
```

#### POST /backup — Create Backup

```bash
# Plaintext backup
curl -X POST http://localhost:9211/backup \
  -H "Authorization: Bearer secret" \
  -H "Content-Type: application/json" \
  -d '{"directory": "./my_backup"}'

# Encrypted backup
curl -X POST http://localhost:9211/backup \
  -H "Authorization: Bearer secret" \
  -H "Content-Type: application/json" \
  -d '{"directory": "./my_backup", "password": "my-encryption-key"}'
```

---

## Python SDK

### Install

```bash
cd clients/python
pip install -e .
```

### Usage

```python
from driftdb import DriftDB

# Connect
db = DriftDB("http://localhost:9211", token="secret")

# Health check
print(db.is_healthy())  # True

# Create nodes
db.create_node(labels=["User"], properties={"name": "Amrit", "age": 25})

# DriftQL query
result = db.query('FIND (u:User) RETURN u.name, u.age')
print(result)
# {"type": "table", "columns": ["u.name", "u.age"], "rows": [["Amrit", "25"]]}

# Find by label
users = db.find("User", returns="n.name")

# Find with filter
adults = db.find("User", where_clause="n.age > 18", returns="n.name")

# Database stats
db.stats()

# Backup (plaintext or encrypted)
db.backup()
db.backup(password="my-secret-key")
```

### API Reference

| Method | Description |
|---|---|
| `DriftDB(url, token)` | Connect to DriftDB REST API |
| `db.query(driftql)` | Execute any DriftQL query |
| `db.create_node(labels, properties)` | Create a node |
| `db.get_node(id)` | Get a node by ID |
| `db.list_nodes()` | List all nodes |
| `db.delete_node(id)` | Soft-delete a node |
| `db.find(label, where_clause, returns)` | Find nodes by label |
| `db.create_edge(src, tgt, type, props)` | Create an edge |
| `db.backup(directory, password)` | Create a backup |
| `db.health()` | Health check |
| `db.is_healthy()` | Quick bool health check |
| `db.stats()` | Database statistics |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   DriftDB                        │
├──────────┬──────────┬───────────┬───────────────┤
│  Graph   │  Vector  │  Temporal │   DriftQL     │
│  Engine  │  Engine  │  Engine   │   Parser      │
├──────────┴──────────┴───────────┴───────────────┤
│              Core Storage (sled)                 │
│         LRU Cache │ WAL │ Event Bus              │
├─────────────────────────────────────────────────┤
│    Security: AES-256-GCM │ Argon2 │ Rate Limit  │
├──────────┬──────────────────────────────────────┤
│  Server  │  REPL │ WebSocket (TLS) │ REST API   │
└──────────┴──────────────────────────────────────┘
```

### Crate Structure

| Crate | Purpose |
|---|---|
| `driftdb-core` | Storage engine, types, security, WAL, events |
| `driftdb-graph` | Nodes, edges, traversal (BFS/DFS/shortest path) |
| `driftdb-vector` | Vector storage, cosine similarity, VP-tree index |
| `driftdb-query` | DriftQL lexer, parser, AST, executor |
| `driftdb-server` | REPL, WebSocket server, REST API, CLI |

### Performance (AMD Ryzen 5 5500U)

| Operation | Speed |
|---|---|
| Cached Lookup | ~2,200,000 ops/sec |
| Cold Lookup | ~430,000 ops/sec |
| Existence Check | ~1,500,000 ops/sec |
| DriftQL Parse | ~830,000 ops/sec |
| Node Creation | ~48,000 ops/sec |
| Edge Creation | ~33,500 ops/sec |
| Vector Attach | ~170,000 ops/sec |
| Similarity Search | ~1,000 ops/sec (128D, top-10) |
