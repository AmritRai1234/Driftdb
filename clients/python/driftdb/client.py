"""
DriftDB Python Client SDK

A lightweight Python client for DriftDB — the next-generation graph database.
Supports DriftQL queries, node CRUD, and backup operations via the REST API.

Usage:
    from driftdb import DriftDB

    db = DriftDB("http://localhost:9211", token="your-token")
    node = db.create_node(labels=["User"], properties={"name": "Amrit", "age": 25})
    results = db.query('FIND (u:User) RETURN u.name')
    db.backup()
"""

import requests
import re
from typing import Optional, Dict, List, Any

# Input validation pattern: alphanumeric + underscore (prevents DriftQL injection)
_SAFE_IDENTIFIER = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$')


class DriftDBError(Exception):
    """Exception raised for DriftDB API errors."""
    pass


class DriftDB:
    """
    DriftDB Python Client.

    Connects to a DriftDB REST API server and provides a Pythonic interface
    for all database operations.

    Args:
        url: Base URL of the DriftDB REST API (e.g., "http://localhost:9211")
        token: Optional Bearer authentication token
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(self, url: str = "http://localhost:9211", token: Optional[str] = None, timeout: int = 30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _request(self, method: str, path: str, json: Optional[dict] = None) -> dict:
        """Make an HTTP request to the DriftDB API."""
        url = f"{self.url}{path}"
        try:
            resp = requests.request(
                method, url,
                json=json,
                headers=self.headers,
                timeout=self.timeout,
            )
        except requests.ConnectionError:
            raise DriftDBError(f"Cannot connect to DriftDB at {self.url}. Is the server running with --serve --rest?")
        except requests.Timeout:
            raise DriftDBError(f"Request to {url} timed out after {self.timeout}s")

        data = resp.json()
        if not data.get("success", False):
            raise DriftDBError(data.get("error", f"HTTP {resp.status_code}"))
        return data.get("data", {})

    # ─── Health ──────────────────────────────────────────────────

    def health(self) -> dict:
        """Check database health and get server stats."""
        return self._request("GET", "/health")

    def is_healthy(self) -> bool:
        """Quick health check — returns True if server is reachable."""
        try:
            info = self.health()
            return info.get("status") == "healthy"
        except Exception:
            return False

    # ─── DriftQL Queries ─────────────────────────────────────────

    def query(self, driftql: str) -> dict:
        """
        Execute a DriftQL query and return the result.

        Args:
            driftql: A DriftQL query string (e.g., 'FIND (n:User) RETURN n.name')

        Returns:
            Query result as a dict (type, columns, rows, etc.)

        Examples:
            >>> db.query('CREATE (u:User {name: "Amrit"})')
            >>> db.query('FIND (u:User) RETURN u.name')
            >>> db.query('SHOW STATS')
        """
        return self._request("POST", "/query", json={"query": driftql})

    # ─── Node CRUD ───────────────────────────────────────────────

    def create_node(self, labels: List[str], properties: Optional[Dict[str, Any]] = None) -> dict:
        """
        Create a new node.

        Args:
            labels: List of labels (e.g., ["User", "Admin"])
            properties: Node properties as a dict

        Returns:
            Created node info (id, labels, properties)
        """
        return self._request("POST", "/nodes", json={
            "labels": labels,
            "properties": properties or {},
        })

    def get_node(self, node_id: str) -> dict:
        """Get a node by its ID."""
        return self._request("GET", f"/nodes/{node_id}")

    def list_nodes(self) -> dict:
        """List all nodes in the database."""
        return self._request("GET", "/nodes")

    def delete_node(self, node_id: str) -> dict:
        """Soft-delete a node by its ID."""
        return self._request("DELETE", f"/nodes/{node_id}")

    # ─── Graph Operations (via DriftQL) ──────────────────────────

    def create_edge(self, source: str, target: str, edge_type: str, properties: Optional[Dict[str, Any]] = None) -> dict:
        """
        Create an edge between two nodes.

        Args:
            source: Source node variable/ID
            target: Target node variable/ID
            edge_type: Relationship type (e.g., "FOLLOWS")
            properties: Edge properties

        Returns:
            Created edge info
        """
        # SECURITY: Validate identifiers to prevent DriftQL injection
        for name, val in [("source", source), ("target", target), ("edge_type", edge_type)]:
            if not _SAFE_IDENTIFIER.match(val):
                raise DriftDBError(f"Invalid {name} '{val}': must be alphanumeric (DriftQL injection blocked)")

        props = ""
        if properties:
            safe_parts = []
            for k, v in properties.items():
                if not _SAFE_IDENTIFIER.match(k):
                    raise DriftDBError(f"Invalid property key '{k}'")
                if isinstance(v, str):
                    # Escape quotes in string values
                    escaped = v.replace('\\', '\\\\').replace('"', '\\"')
                    safe_parts.append(f'{k}: "{escaped}"')
                elif isinstance(v, (int, float)):
                    safe_parts.append(f'{k}: {v}')
                else:
                    raise DriftDBError(f"Unsupported property type for '{k}': {type(v)}")
            props = f" {{{', '.join(safe_parts)}}}"
        return self.query(f'LINK ({source})-[:{edge_type}{props}]->({target})')

    def find(self, label: str, where_clause: Optional[str] = None, returns: Optional[str] = None) -> dict:
        """
        Find nodes by label with optional filtering.

        Args:
            label: Node label to search for
            where_clause: Optional WHERE clause (e.g., "n.age > 18")
            returns: Optional RETURN clause (e.g., "n.name, n.age")

        Returns:
            Query result with matching nodes
        """
        # SECURITY: Validate label to prevent DriftQL injection
        if not _SAFE_IDENTIFIER.match(label):
            raise DriftDBError(f"Invalid label '{label}': must be alphanumeric")
        q = f"FIND (n:{label})"
        if where_clause:
            q += f" WHERE {where_clause}"
        if returns:
            q += f" RETURN {returns}"
        return self.query(q)

    def stats(self) -> dict:
        """Get database statistics."""
        return self.query("SHOW STATS")

    # ─── Backup ──────────────────────────────────────────────────

    def backup(self, directory: str = "./drift_backups", password: Optional[str] = None) -> dict:
        """
        Create a database backup.

        Args:
            directory: Backup directory path
            password: Optional password for encrypted backup

        Returns:
            Backup path info
        """
        payload: Dict[str, Any] = {"directory": directory}
        if password:
            payload["password"] = password
        return self._request("POST", "/backup", json=payload)

    # ─── Convenience ─────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"DriftDB(url='{self.url}')"

    def __str__(self) -> str:
        try:
            info = self.health()
            return f"DriftDB @ {self.url} — {info.get('status', 'unknown')}"
        except Exception:
            return f"DriftDB @ {self.url} — disconnected"
