# DriftDB Python Client

Python SDK for [DriftDB](https://github.com/amrit/driftdb) — a next-generation graph database.

## Install

```bash
pip install -e .
```

## Quick Start

```python
from driftdb import DriftDB

# Connect (start server with: driftdb --serve --rest --ws-token secret)
db = DriftDB("http://localhost:9211", token="secret")

# Health check
print(db.is_healthy())  # True

# Create nodes
db.create_node(labels=["User"], properties={"name": "Amrit", "age": 25})
db.create_node(labels=["User"], properties={"name": "Kai", "age": 30})

# DriftQL queries
result = db.query('FIND (u:User) RETURN u.name, u.age')
print(result)  # {"type": "table", "columns": [...], "rows": [...]}

# Find by label
users = db.find("User", returns="n.name")

# Get stats
stats = db.stats()

# Backup
db.backup(password="my-secret")
```

## API Reference

| Method | Description |
|---|---|
| `DriftDB(url, token)` | Connect to DriftDB |
| `db.query(driftql)` | Execute any DriftQL query |
| `db.create_node(labels, properties)` | Create a node |
| `db.get_node(id)` | Get a node by ID |
| `db.list_nodes()` | List all nodes |
| `db.delete_node(id)` | Soft-delete a node |
| `db.find(label, where, returns)` | Find nodes by label |
| `db.create_edge(src, tgt, type)` | Create an edge |
| `db.backup(dir, password)` | Create a backup |
| `db.health()` | Health check |
| `db.stats()` | Database stats |
