"""
memory_audit.py — OpenClaw memory backend & knowledge graph audit tools

Tools:
  openclaw_pgvector_memory_check    — validates pgvector configuration for semantic memory
  openclaw_knowledge_graph_check    — audits knowledge graph integrity (orphans, cycles, TTL)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_RECOMMENDED_HNSW_PARAMS = {
    "m": (8, 64),             # HNSW M parameter range
    "ef_construction": (64, 512),  # ef_construction range
}

_COMMON_DIMENSIONS = {128, 256, 384, 512, 768, 1024, 1536, 3072}

_VALID_DISTANCE_METRICS = {"cosine", "l2", "inner_product", "ip"}

_GRAPH_BACKENDS = {"neo4j", "memgraph", "neptune", "arangodb", "json", "sqlite"}


# ── Tool: openclaw_pgvector_memory_check ─────────────────────────────────────

async def openclaw_pgvector_memory_check(
    config_path: str | None = None,
    connection_string: str | None = None,
    config_data: dict | None = None,
) -> dict[str, Any]:
    """
    Validate pgvector configuration for OpenClaw semantic memory backend.

    Checks:
      - pgvector extension is referenced in config
      - Index type (HNSW recommended over IVFFlat for < 1M rows)
      - Dimensions match model output size
      - Distance metric is set (cosine/l2/inner_product)
      - HNSW parameters (M, ef_construction) are within recommended ranges
      - Connection string doesn't embed credentials in plaintext

    Args:
        config_path: Path to OpenClaw config JSON file.
        connection_string: Optional PostgreSQL connection string to validate.
        config_data: Optional inline config dict (for testing).

    Returns:
        dict with status, findings, recommendations.
    """
    findings: list[dict[str, str]] = []
    config: dict[str, Any] = {}

    # Load config
    if config_data:
        config = config_data
    elif config_path:
        p = Path(config_path)
        if not p.exists():
            return {"ok": False, "error": f"Config not found: {config_path}"}
        try:
            config = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Invalid JSON: {exc}"}
    else:
        return {"ok": False, "error": "Provide config_path or config_data"}

    # Extract memory/vector config section
    memory_cfg = (
        config.get("memory", {}).get("vector", {})
        or config.get("vector", {})
        or config.get("pgvector", {})
    )

    if not memory_cfg:
        return {
            "ok": True,
            "status": "info",
            "findings": [{"severity": "INFO", "message": "No pgvector/vector memory config found."}],
            "recommendations": ["Add a memory.vector section to enable semantic memory."],
        }

    # 1. Check extension reference
    backend = memory_cfg.get("backend", memory_cfg.get("provider", ""))
    if backend and "pgvector" not in str(backend).lower() and "pg" not in str(backend).lower():
        findings.append({
            "severity": "INFO",
            "message": f"Vector backend is '{backend}', not pgvector. Skipping pgvector-specific checks.",
        })
        return {
            "ok": True,
            "status": "ok",
            "findings": findings,
            "recommendations": [],
        }

    # 2. Check index type
    index_type = memory_cfg.get("index_type", memory_cfg.get("index", "")).lower()
    if index_type:
        if "ivfflat" in index_type:
            findings.append({
                "severity": "MEDIUM",
                "message": f"Index type is '{index_type}'. HNSW is recommended for <1M rows (better recall, no retraining).",
            })
        elif "hnsw" in index_type:
            findings.append({"severity": "OK", "message": "HNSW index type — recommended."})

            # Check HNSW params
            m_val = memory_cfg.get("m") or memory_cfg.get("hnsw_m")
            ef_val = memory_cfg.get("ef_construction") or memory_cfg.get("hnsw_ef_construction")

            if m_val is not None:
                m_lo, m_hi = _RECOMMENDED_HNSW_PARAMS["m"]
                if not (m_lo <= int(m_val) <= m_hi):
                    findings.append({
                        "severity": "MEDIUM",
                        "message": f"HNSW M={m_val} outside recommended range [{m_lo}, {m_hi}].",
                    })
            if ef_val is not None:
                ef_lo, ef_hi = _RECOMMENDED_HNSW_PARAMS["ef_construction"]
                if not (ef_lo <= int(ef_val) <= ef_hi):
                    findings.append({
                        "severity": "MEDIUM",
                        "message": f"HNSW ef_construction={ef_val} outside recommended range [{ef_lo}, {ef_hi}].",
                    })
        else:
            findings.append({
                "severity": "HIGH",
                "message": f"Unknown index type '{index_type}'. Use HNSW for best balance of speed and recall.",
            })
    else:
        findings.append({
            "severity": "HIGH",
            "message": "No index type specified. Default sequential scan will be very slow. Set index_type to 'hnsw'.",
        })

    # 3. Check dimensions
    dims = memory_cfg.get("dimensions", memory_cfg.get("dim"))
    if dims is not None:
        dims = int(dims)
        if dims not in _COMMON_DIMENSIONS:
            findings.append({
                "severity": "MEDIUM",
                "message": f"Dimensions={dims} is not a common embedding size. Common: {sorted(_COMMON_DIMENSIONS)}.",
            })
        else:
            findings.append({"severity": "OK", "message": f"Dimensions={dims} — common embedding size."})
    else:
        findings.append({
            "severity": "HIGH",
            "message": "No dimensions specified. This must match your embedding model output size.",
        })

    # 4. Check distance metric
    metric = memory_cfg.get("distance", memory_cfg.get("metric", memory_cfg.get("distance_metric", ""))).lower()
    if metric:
        if metric in _VALID_DISTANCE_METRICS:
            findings.append({"severity": "OK", "message": f"Distance metric '{metric}' — valid."})
        else:
            findings.append({
                "severity": "HIGH",
                "message": f"Unknown distance metric '{metric}'. Use one of: {sorted(_VALID_DISTANCE_METRICS)}.",
            })
    else:
        findings.append({
            "severity": "MEDIUM",
            "message": "No distance metric specified. Default varies by extension. Set explicitly for reproducibility.",
        })

    # 5. Check connection string for embedded credentials
    conn_str = connection_string or memory_cfg.get("connection_string", memory_cfg.get("dsn", ""))
    if conn_str:
        if re.search(r"://[^:]+:[^@]+@", conn_str):
            findings.append({
                "severity": "CRITICAL",
                "message": "Connection string contains embedded credentials. Use environment variable reference instead.",
            })
        else:
            findings.append({"severity": "OK", "message": "Connection string does not embed credentials."})

    # Determine overall status
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    else:
        status = "ok"

    recommendations = []
    if any(f["severity"] in ("HIGH", "CRITICAL") for f in findings):
        recommendations.append("Review and fix HIGH/CRITICAL findings before deploying semantic memory.")
    if not index_type:
        recommendations.append("Add index_type: 'hnsw' for optimal query performance.")
    if not dims:
        recommendations.append("Set dimensions to match your embedding model (e.g., 1536 for text-embedding-3-small).")

    return {
        "ok": True,
        "status": status,
        "findings": findings,
        "recommendations": recommendations,
    }


# ── Tool: openclaw_knowledge_graph_check ─────────────────────────────────────

async def openclaw_knowledge_graph_check(
    config_path: str | None = None,
    config_data: dict | None = None,
    graph_data_path: str | None = None,
) -> dict[str, Any]:
    """
    Audit knowledge graph integrity for OpenClaw persistent memory.

    Checks:
      - Graph backend is configured (neo4j, memgraph, json, sqlite, etc.)
      - TTL policy exists for automatic cleanup
      - Orphan node detection (nodes with no edges)
      - Cycle detection in directional relationship graphs
      - Node/edge count and density metrics
      - Backup configuration

    Args:
        config_path: Path to OpenClaw config JSON.
        config_data: Optional inline config dict (for testing).
        graph_data_path: Optional path to a JSON graph export for deeper analysis.

    Returns:
        dict with status, findings, metrics, recommendations.
    """
    findings: list[dict[str, str]] = []
    metrics: dict[str, Any] = {}
    config: dict[str, Any] = {}

    # Load config
    if config_data:
        config = config_data
    elif config_path:
        p = Path(config_path)
        if not p.exists():
            return {"ok": False, "error": f"Config not found: {config_path}"}
        try:
            config = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Invalid JSON: {exc}"}
    else:
        return {"ok": False, "error": "Provide config_path or config_data"}

    # Extract knowledge graph config
    kg_cfg = (
        config.get("memory", {}).get("graph", {})
        or config.get("knowledge_graph", {})
        or config.get("graph", {})
    )

    if not kg_cfg:
        return {
            "ok": True,
            "status": "info",
            "findings": [{"severity": "INFO", "message": "No knowledge graph config found."}],
            "metrics": {},
            "recommendations": ["Add a memory.graph section to enable knowledge graph memory."],
        }

    # 1. Check backend
    backend = kg_cfg.get("backend", kg_cfg.get("provider", kg_cfg.get("type", ""))).lower()
    if backend:
        if backend in _GRAPH_BACKENDS:
            findings.append({"severity": "OK", "message": f"Graph backend '{backend}' — supported."})
        else:
            findings.append({
                "severity": "MEDIUM",
                "message": f"Unknown graph backend '{backend}'. Supported: {sorted(_GRAPH_BACKENDS)}.",
            })
    else:
        findings.append({
            "severity": "HIGH",
            "message": "No graph backend specified. Set memory.graph.backend.",
        })

    # 2. Check TTL policy
    ttl = kg_cfg.get("ttl", kg_cfg.get("ttl_seconds", kg_cfg.get("expiry")))
    if ttl is not None:
        ttl_val = int(ttl)
        if ttl_val < 3600:
            findings.append({
                "severity": "MEDIUM",
                "message": f"TTL={ttl_val}s is very short (<1h). Memories may be lost before they're useful.",
            })
        elif ttl_val > 86400 * 365:
            findings.append({
                "severity": "MEDIUM",
                "message": f"TTL={ttl_val}s (>{ttl_val // 86400} days). Consider automatic pruning to prevent unbounded growth.",
            })
        else:
            findings.append({"severity": "OK", "message": f"TTL={ttl_val}s — reasonable."})
    else:
        findings.append({
            "severity": "HIGH",
            "message": "No TTL policy. Graph will grow unbounded. Set memory.graph.ttl_seconds.",
        })

    # 3. Check backup config
    backup = kg_cfg.get("backup", kg_cfg.get("snapshot"))
    if backup:
        findings.append({"severity": "OK", "message": "Backup/snapshot configuration present."})
    else:
        findings.append({
            "severity": "MEDIUM",
            "message": "No backup configuration for knowledge graph. Add backup/snapshot settings.",
        })

    # 4. Check max_nodes limit
    max_nodes = kg_cfg.get("max_nodes", kg_cfg.get("node_limit"))
    if max_nodes:
        findings.append({"severity": "OK", "message": f"Node limit set to {max_nodes}."})
    else:
        findings.append({
            "severity": "MEDIUM",
            "message": "No max_nodes limit. Graph could grow unbounded in memory.",
        })

    # 5. If graph data export provided, analyze it
    if graph_data_path:
        gp = Path(graph_data_path)
        if gp.exists():
            try:
                graph_data = json.loads(gp.read_text())
                graph_metrics = _analyze_graph(graph_data)
                metrics.update(graph_metrics)

                if graph_metrics.get("orphan_nodes", 0) > 0:
                    orphan_pct = graph_metrics["orphan_nodes"] / max(graph_metrics["total_nodes"], 1) * 100
                    sev = "HIGH" if orphan_pct > 20 else "MEDIUM" if orphan_pct > 5 else "INFO"
                    findings.append({
                        "severity": sev,
                        "message": (
                            f"{graph_metrics['orphan_nodes']} orphan node(s) "
                            f"({orphan_pct:.1f}% of total). Consider pruning."
                        ),
                    })

                if graph_metrics.get("has_cycles"):
                    findings.append({
                        "severity": "MEDIUM",
                        "message": "Cycles detected in graph. Check if intentional (e.g., bidirectional refs).",
                    })

            except (json.JSONDecodeError, KeyError) as exc:
                findings.append({"severity": "INFO", "message": f"Could not parse graph data: {exc}"})

    # Determine severity
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    else:
        status = "ok"

    recommendations = []
    if not ttl:
        recommendations.append("Add TTL policy (e.g., 30 days) to prevent unbounded growth.")
    if not backup:
        recommendations.append("Configure periodic graph snapshots for disaster recovery.")
    if not max_nodes:
        recommendations.append("Set max_nodes to cap memory usage (e.g., 100000).")

    return {
        "ok": True,
        "status": status,
        "findings": findings,
        "metrics": metrics,
        "recommendations": recommendations,
    }


def _analyze_graph(data: dict[str, Any]) -> dict[str, Any]:
    """Analyze a JSON graph export for metrics."""
    nodes = data.get("nodes", [])
    edges = data.get("edges", data.get("relationships", data.get("links", [])))

    total_nodes = len(nodes)
    total_edges = len(edges) if isinstance(edges, list) else 0

    # Find orphan nodes (no edges)
    connected_ids: set[str] = set()
    for edge in (edges if isinstance(edges, list) else []):
        src = edge.get("source") or edge.get("from") or edge.get("src")
        tgt = edge.get("target") or edge.get("to") or edge.get("dst")
        if src:
            connected_ids.add(str(src))
        if tgt:
            connected_ids.add(str(tgt))

    node_ids = {str(n.get("id", i)) for i, n in enumerate(nodes)}
    orphans = node_ids - connected_ids

    # Simple cycle detection via DFS
    adj: dict[str, list[str]] = {}
    for edge in (edges if isinstance(edges, list) else []):
        src = str(edge.get("source") or edge.get("from") or edge.get("src", ""))
        tgt = str(edge.get("target") or edge.get("to") or edge.get("dst", ""))
        if src and tgt:
            adj.setdefault(src, []).append(tgt)

    has_cycles = _detect_cycle(adj)

    density = (2 * total_edges) / (total_nodes * (total_nodes - 1)) if total_nodes > 1 else 0.0

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "orphan_nodes": len(orphans),
        "has_cycles": has_cycles,
        "density": round(density, 4),
    }


def _detect_cycle(adj: dict[str, list[str]]) -> bool:
    """DFS cycle detection for directed graph."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n: WHITE for n in adj}

    def dfs(u: str) -> bool:
        color[u] = GRAY
        for v in adj.get(u, []):
            if v not in color:
                color[v] = WHITE
            if color[v] == GRAY:
                return True
            if color[v] == WHITE and dfs(v):
                return True
        color[u] = BLACK
        return False

    for node in list(adj.keys()):
        if color.get(node, WHITE) == WHITE:
            if dfs(node):
                return True
    return False


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "openclaw_pgvector_memory_check",
        "title": "pgvector Memory Config Check",
        "description": (
            "Validates pgvector configuration for semantic memory: index type (HNSW recommended), "
            "dimensions, distance metric, HNSW params (M, ef_construction), and connection string "
            "credential exposure. Gap T3/issue #15093."
        ),
        "category": "memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_pgvector_memory_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to OpenClaw config JSON.",
                },
                "connection_string": {
                    "type": "string",
                    "description": "Optional PostgreSQL connection string to validate.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "openclaw_knowledge_graph_check",
        "title": "Knowledge Graph Integrity",
        "description": (
            "Audits knowledge graph integrity: backend validation, TTL policy, orphan node detection, "
            "cycle detection, density metrics, and backup configuration. Gap T9/issue #7783."
        ),
        "category": "memory",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "handler": openclaw_knowledge_graph_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean", "description": "Whether the check passed"},
                "severity": {"type": "string", "enum": ["OK", "INFO", "MEDIUM", "HIGH", "CRITICAL"]},
                "findings": {"type": "array", "items": {"type": "string"}, "description": "List of findings"},
                "finding_count": {"type": "integer", "description": "Number of findings"},
                "config_path": {"type": "string", "description": "Path to config file analyzed"}
            },
            "required": ["ok", "severity", "findings", "finding_count"]
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to OpenClaw config JSON.",
                },
                "graph_data_path": {
                    "type": "string",
                    "description": "Optional path to JSON graph export for deep analysis.",
                },
            },
            "required": [],
        },
    },
]
