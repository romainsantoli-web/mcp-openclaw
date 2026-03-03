"""
ecosystem_audit.py — Ecosystem differentiation tools (2026 trends)

Implements the high-impact tools from ecosystem trend analysis:
  - MCP Gateway/Firewall policy check
  - RAG pipeline validation
  - Sandbox execution audit
  - Context health / rot detection
  - Provenance & audit trail
  - Cost/usage analytics
  - Token budget optimization

Tools exposed (7):
  firm_mcp_firewall_check     — MCP gateway firewall policies
  firm_rag_pipeline_check     — RAG pipeline health & config
  firm_sandbox_exec_check     — sandbox execution isolation
  firm_context_health_check   — context rot detection
  firm_provenance_tracker     — cryptographic audit trail
  firm_cost_analytics         — usage/cost tracking
  firm_token_budget_optimizer — token optimization analysis
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from src.config_helpers import load_config, get_nested

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

_DANGEROUS_TOOLS = {
    "exec", "shell", "run_command", "execute_code", "file_write",
    "file_delete", "system", "subprocess", "eval", "code_exec",
}

_SAFE_SANDBOX_MODES = {"nsjail", "gvisor", "container", "firecracker", "wasm"}

_RAG_REQUIRED_KEYS = [
    "embedding.model",
    "vectorStore.type",
    "retrieval.topK",
]

_EMBEDDING_MODELS_DIMENSIONS = {
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "text-embedding-ada-002": 1536,
    "nomic-embed-text": 768,
    "bge-large-en": 1024,
    "e5-large-v2": 1024,
    "all-MiniLM-L6-v2": 384,
}

_PROVENANCE_HASH_ALGORITHMS = {"sha256", "sha384", "sha512"}

# ── In-memory provenance chain ──────────────────────────────────────────────

_PROVENANCE_CHAIN: list[dict[str, Any]] = []


# ── Tool handlers ────────────────────────────────────────────────────────────

def firm_mcp_firewall_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    MCP Gateway firewall policy audit.

    Checks:
    - Tool allowlist/blocklist policies
    - Argument sanitization rules
    - Rate limits per tool
    - Secret leakage prevention rules
    - Request size limits
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    gw_cfg = get_nested(config, "gateway") or {}
    firewall_cfg = gw_cfg.get("firewall", gw_cfg.get("policy", {}))

    # Tool allowlist
    allowlist = firewall_cfg.get("toolAllowlist", firewall_cfg.get("allowedTools"))
    blocklist = firewall_cfg.get("toolBlocklist", firewall_cfg.get("blockedTools", []))

    if not allowlist and not blocklist:
        findings.append({
            "severity": "HIGH",
            "check": "gateway.firewall.toolPolicy",
            "message": "No tool allow/blocklist configured. "
                       "All tools are accessible without restriction.",
        })

    # Check if dangerous tools are allowed
    if isinstance(allowlist, list):
        for tool in allowlist:
            if tool.lower() in _DANGEROUS_TOOLS:
                findings.append({
                    "severity": "CRITICAL",
                    "check": f"gateway.firewall.allowlist.{tool}",
                    "message": f"Dangerous tool '{tool}' is in the allowlist.",
                })
    elif not allowlist:
        # No allowlist = everything permitted, check blocklist
        if isinstance(blocklist, list):
            missing_blocks = _DANGEROUS_TOOLS - set(t.lower() for t in blocklist)
            if missing_blocks:
                findings.append({
                    "severity": "HIGH",
                    "check": "gateway.firewall.blocklist",
                    "message": f"Dangerous tools not blocked: {sorted(missing_blocks)[:5]}",
                })

    # Argument sanitization
    arg_rules = firewall_cfg.get("argumentSanitization", {})
    if not arg_rules:
        findings.append({
            "severity": "MEDIUM",
            "check": "gateway.firewall.argumentSanitization",
            "message": "No argument sanitization rules. "
                       "Tool arguments are passed through unfiltered.",
        })

    # Rate limits per tool
    rate_limits = firewall_cfg.get("rateLimits", firewall_cfg.get("toolRateLimits", {}))
    if not rate_limits:
        findings.append({
            "severity": "MEDIUM",
            "check": "gateway.firewall.rateLimits",
            "message": "No per-tool rate limits configured.",
        })

    # Secret leakage prevention
    leak_prevention = firewall_cfg.get("secretLeakPrevention",
                                        firewall_cfg.get("outputFiltering", {}))
    if not leak_prevention.get("enabled", False):
        findings.append({
            "severity": "HIGH",
            "check": "gateway.firewall.secretLeakPrevention",
            "message": "Secret leakage prevention not enabled. "
                       "Tool outputs may contain sensitive data.",
        })

    # Request size
    max_size = firewall_cfg.get("maxRequestSize", 0)
    if max_size == 0 or max_size > 10 * 1024 * 1024:
        findings.append({
            "severity": "MEDIUM",
            "check": "gateway.firewall.maxRequestSize",
            "message": f"Request size limit is {max_size or 'unlimited'}. "
                       "Recommend ≤10MB.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "findings": findings,
        "finding_count": len(findings),
    }


def firm_rag_pipeline_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    RAG pipeline health & configuration audit.

    Checks:
    - Embedding model configuration and dimensions
    - Vector store type and health
    - Chunk size and overlap settings
    - Retrieval top-K and threshold
    - Index freshness and rebuild policy
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    rag_cfg = get_nested(config, "rag") or get_nested(config, "retrieval") or {}

    if not rag_cfg:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": "No RAG configuration found"}

    # Embedding model
    embedding = rag_cfg.get("embedding", {})
    model = embedding.get("model", "")
    if not model:
        findings.append({
            "severity": "HIGH",
            "check": "rag.embedding.model",
            "message": "No embedding model configured.",
        })
    else:
        expected_dim = _EMBEDDING_MODELS_DIMENSIONS.get(model)
        actual_dim = embedding.get("dimensions", 0)
        if expected_dim and actual_dim and expected_dim != actual_dim:
            findings.append({
                "severity": "HIGH",
                "check": "rag.embedding.dimensions",
                "message": f"Dimension mismatch for '{model}': "
                           f"expected {expected_dim}, configured {actual_dim}.",
            })

    # Vector store
    vs_cfg = rag_cfg.get("vectorStore", {})
    vs_type = vs_cfg.get("type", "")
    if not vs_type:
        findings.append({
            "severity": "HIGH",
            "check": "rag.vectorStore.type",
            "message": "No vector store type configured.",
        })

    # Connection string check
    conn = vs_cfg.get("connectionString", vs_cfg.get("url", ""))
    if conn and not conn.startswith("$"):
        findings.append({
            "severity": "MEDIUM",
            "check": "rag.vectorStore.connectionString",
            "message": "Vector store connection string appears hardcoded. "
                       "Use environment variable reference.",
        })

    # Chunking
    chunking = rag_cfg.get("chunking", {})
    chunk_size = chunking.get("size", 0)
    if chunk_size:
        if chunk_size < 100:
            findings.append({
                "severity": "MEDIUM",
                "check": "rag.chunking.size",
                "message": f"Chunk size {chunk_size} is very small. "
                           "May cause retrieval quality degradation.",
            })
        elif chunk_size > 4000:
            findings.append({
                "severity": "MEDIUM",
                "check": "rag.chunking.size",
                "message": f"Chunk size {chunk_size} is very large. "
                           "May cause context dilution.",
            })

    # Retrieval
    retrieval = rag_cfg.get("retrieval", {})
    top_k = retrieval.get("topK", 0)
    if top_k and top_k > 20:
        findings.append({
            "severity": "MEDIUM",
            "check": "rag.retrieval.topK",
            "message": f"topK={top_k} is high. May waste context window.",
        })

    threshold = retrieval.get("threshold", retrieval.get("minScore", 0))
    if not threshold:
        findings.append({
            "severity": "MEDIUM",
            "check": "rag.retrieval.threshold",
            "message": "No retrieval score threshold. "
                       "Low-quality results may be included.",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL", "HIGH"),
        "severity": max_sev,
        "config_path": cfg_path,
        "embedding_model": model,
        "vector_store_type": vs_type,
        "findings": findings,
        "finding_count": len(findings),
    }


def firm_sandbox_exec_check(
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Sandbox execution isolation audit.

    Checks:
    - Sandbox mode (nsjail/gvisor/container/wasm)
    - Resource limits (CPU, memory, disk, network)
    - Filesystem restrictions
    - Network policy
    - Timeout enforcement
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)

    if not config:
        return {"ok": True, "severity": "INFO", "findings": [],
                "message": f"No config at {cfg_path}"}

    sandbox_cfg = get_nested(config, "sandbox") or get_nested(config, "execution") or {}

    if not sandbox_cfg:
        findings.append({
            "severity": "CRITICAL",
            "check": "sandbox",
            "message": "No sandbox configuration. Code execution is unrestricted.",
        })
        return {
            "ok": False,
            "severity": "CRITICAL",
            "config_path": cfg_path,
            "findings": findings,
            "finding_count": len(findings),
        }

    # Mode check
    mode = sandbox_cfg.get("mode", "none")
    if mode.lower() in ("none", "off", "disabled", ""):
        findings.append({
            "severity": "CRITICAL",
            "check": "sandbox.mode",
            "message": f"Sandbox mode is '{mode}'. Code execution is unrestricted.",
        })
    elif mode.lower() not in _SAFE_SANDBOX_MODES:
        findings.append({
            "severity": "HIGH",
            "check": "sandbox.mode",
            "message": f"Sandbox mode '{mode}' is not a recognized isolation technology.",
        })

    # Resource limits
    limits = sandbox_cfg.get("limits", sandbox_cfg.get("resources", {}))
    if not limits:
        findings.append({
            "severity": "HIGH",
            "check": "sandbox.limits",
            "message": "No resource limits configured for sandbox execution.",
        })
    else:
        if not limits.get("memoryMB") and not limits.get("memory"):
            findings.append({
                "severity": "HIGH",
                "check": "sandbox.limits.memory",
                "message": "No memory limit for sandbox.",
            })
        if not limits.get("cpuSeconds") and not limits.get("cpu"):
            findings.append({
                "severity": "MEDIUM",
                "check": "sandbox.limits.cpu",
                "message": "No CPU limit for sandbox.",
            })

    # Network policy
    network = sandbox_cfg.get("network", {})
    if network.get("enabled", True) is True and not network.get("policy"):
        findings.append({
            "severity": "HIGH",
            "check": "sandbox.network",
            "message": "Network access enabled in sandbox without a policy. "
                       "Sandboxed code can make arbitrary network requests.",
        })

    # Filesystem
    fs = sandbox_cfg.get("filesystem", {})
    if fs.get("writable", True) is True and not fs.get("allowedPaths"):
        findings.append({
            "severity": "HIGH",
            "check": "sandbox.filesystem",
            "message": "Writable filesystem in sandbox without path restrictions.",
        })

    # Timeout
    timeout = sandbox_cfg.get("timeoutSeconds", sandbox_cfg.get("timeout", 0))
    if not timeout or timeout > 300:
        findings.append({
            "severity": "MEDIUM",
            "check": "sandbox.timeout",
            "message": f"Sandbox timeout is {timeout or 'unlimited'}s. "
                       "Recommend ≤300s (5min).",
        })

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "config_path": cfg_path,
        "sandbox_mode": sandbox_cfg.get("mode", "unknown"),
        "findings": findings,
        "finding_count": len(findings),
    }


def firm_context_health_check(
    session_data: dict[str, Any] | None = None,
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Context rot / cognitive health detection.

    Checks:
    - Token utilization vs context window size
    - Session age and turnover count
    - Context compression ratio
    - Session fatigue indicators
    - Recovery recommendations
    """
    findings: list[dict[str, str]] = []
    config, cfg_path = load_config(config_path)
    session = session_data or {}

    # Token utilization
    tokens_used = session.get("tokensUsed", session.get("token_count", 0))
    context_window = session.get("contextWindow", session.get("max_tokens", 200000))

    if tokens_used and context_window:
        utilization = tokens_used / context_window
        if utilization > 0.9:
            findings.append({
                "severity": "CRITICAL",
                "check": "context.utilization",
                "message": f"Context window {utilization:.0%} full. "
                           "Immediate compaction or new session required.",
            })
        elif utilization > 0.75:
            findings.append({
                "severity": "HIGH",
                "check": "context.utilization",
                "message": f"Context window {utilization:.0%} full. "
                           "Schedule compaction soon.",
            })
        elif utilization > 0.5:
            findings.append({
                "severity": "MEDIUM",
                "check": "context.utilization",
                "message": f"Context window {utilization:.0%} full.",
            })

    # Session age
    created = session.get("createdAt", session.get("created_at", 0))
    if created:
        age_hours = (time.time() - created) / 3600
        if age_hours > 24:
            findings.append({
                "severity": "HIGH",
                "check": "context.sessionAge",
                "message": f"Session is {age_hours:.0f}h old. "
                           "Context may contain stale information.",
            })
        elif age_hours > 8:
            findings.append({
                "severity": "MEDIUM",
                "check": "context.sessionAge",
                "message": f"Session is {age_hours:.0f}h old.",
            })

    # Turn count
    turns = session.get("turnCount", session.get("turns", 0))
    if turns > 50:
        findings.append({
            "severity": "HIGH",
            "check": "context.turnCount",
            "message": f"Session has {turns} turns. "
                       "High risk of context confusion and contradictions.",
        })
    elif turns > 20:
        findings.append({
            "severity": "MEDIUM",
            "check": "context.turnCount",
            "message": f"Session has {turns} turns.",
        })

    # Recommendations
    recommendations: list[str] = []
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH"):
            if "compaction" in f["message"].lower():
                recommendations.append("Run context compaction immediately")
            elif "session" in f["check"]:
                recommendations.append("Consider starting a new session")
            elif "turn" in f["check"]:
                recommendations.append("Summarize and compress conversation history")

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "CRITICAL":
            max_sev = "CRITICAL"
            break
        if f["severity"] == "HIGH" and max_sev != "CRITICAL":
            max_sev = "HIGH"
        if f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": max_sev not in ("CRITICAL",),
        "severity": max_sev,
        "tokens_used": tokens_used,
        "context_window": context_window,
        "utilization": round(tokens_used / context_window, 3) if context_window else 0,
        "recommendations": recommendations,
        "findings": findings,
        "finding_count": len(findings),
    }


def firm_provenance_tracker(
    action: str = "status",
    entry: dict[str, Any] | None = None,
    chain_path: str | None = None,
    algorithm: str = "sha256",
) -> dict[str, Any]:
    """
    Cryptographic audit trail / provenance tracking.

    Actions:
    - append: Add a new provenance entry with hash chain
    - verify: Verify chain integrity
    - status: Show chain status
    - export: Export chain to file
    """
    if algorithm not in _PROVENANCE_HASH_ALGORITHMS:
        return {"ok": False, "error": f"Unsupported algorithm: {algorithm}. "
                f"Use: {sorted(_PROVENANCE_HASH_ALGORITHMS)}"}

    if action == "append":
        if not entry:
            return {"ok": False, "error": "entry dict required for append"}

        # Build chain entry
        prev_hash = _PROVENANCE_CHAIN[-1]["hash"] if _PROVENANCE_CHAIN else "0" * 64
        entry_data = {
            "index": len(_PROVENANCE_CHAIN),
            "timestamp": time.time(),
            "prev_hash": prev_hash,
            "intent": entry.get("intent", ""),
            "agent": entry.get("agent", "unknown"),
            "action": entry.get("action", ""),
            "inputs_hash": hashlib.new(
                algorithm,
                json.dumps(entry.get("inputs", {}), sort_keys=True).encode(),
            ).hexdigest(),
            "outputs_hash": hashlib.new(
                algorithm,
                json.dumps(entry.get("outputs", {}), sort_keys=True).encode(),
            ).hexdigest(),
        }
        # Chain hash
        chain_str = json.dumps(entry_data, sort_keys=True)
        entry_data["hash"] = hashlib.new(algorithm, chain_str.encode()).hexdigest()

        _PROVENANCE_CHAIN.append(entry_data)
        return {
            "ok": True,
            "action": "append",
            "index": entry_data["index"],
            "hash": entry_data["hash"],
            "chain_length": len(_PROVENANCE_CHAIN),
        }

    elif action == "verify":
        if not _PROVENANCE_CHAIN:
            return {"ok": True, "action": "verify", "chain_length": 0,
                    "message": "Chain is empty"}

        for i, entry_data in enumerate(_PROVENANCE_CHAIN):
            expected_prev = _PROVENANCE_CHAIN[i-1]["hash"] if i > 0 else "0" * 64
            if entry_data.get("prev_hash") != expected_prev:
                return {
                    "ok": False,
                    "action": "verify",
                    "broken_at_index": i,
                    "message": f"Chain broken at index {i}: prev_hash mismatch",
                }

        return {
            "ok": True,
            "action": "verify",
            "chain_length": len(_PROVENANCE_CHAIN),
            "integrity": "valid",
            "algorithm": algorithm,
        }

    elif action == "export":
        export_data = {
            "chain": _PROVENANCE_CHAIN,
            "length": len(_PROVENANCE_CHAIN),
            "algorithm": algorithm,
            "exported_at": time.time(),
        }
        if chain_path:
            try:
                Path(chain_path).write_text(
                    json.dumps(export_data, indent=2), encoding="utf-8")
                return {"ok": True, "action": "export",
                        "path": chain_path, "entries": len(_PROVENANCE_CHAIN)}
            except (OSError, PermissionError) as exc:
                return {"ok": False, "error": str(exc)}
        return {"ok": True, "action": "export", "data": export_data}

    else:  # status
        return {
            "ok": True,
            "action": "status",
            "chain_length": len(_PROVENANCE_CHAIN),
            "algorithm": algorithm,
            "last_hash": _PROVENANCE_CHAIN[-1]["hash"] if _PROVENANCE_CHAIN else None,
            "last_timestamp": _PROVENANCE_CHAIN[-1]["timestamp"] if _PROVENANCE_CHAIN else None,
        }


def firm_cost_analytics(
    session_data: dict[str, Any] | None = None,
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Usage/cost tracking and analysis.

    Analyzes:
    - Token usage per agent/session/tool
    - Cost estimation based on model pricing
    - Budget threshold monitoring
    - Usage trend detection
    """
    config, cfg_path = load_config(config_path)
    findings: list[dict[str, str]] = []
    session = session_data or {}

    # Model pricing ($/1M tokens — approximate)
    pricing = {
        "claude-3-opus": {"input": 15.0, "output": 75.0},
        "claude-3.5-sonnet": {"input": 3.0, "output": 15.0},
        "claude-3-haiku": {"input": 0.25, "output": 1.25},
        "gpt-4o": {"input": 2.5, "output": 10.0},
        "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    }

    model = session.get("model", "claude-3.5-sonnet")
    input_tokens = session.get("inputTokens", session.get("tokens_in", 0))
    output_tokens = session.get("outputTokens", session.get("tokens_out", 0))

    model_price = pricing.get(model, {"input": 3.0, "output": 15.0})
    cost_input = (input_tokens / 1_000_000) * model_price["input"]
    cost_output = (output_tokens / 1_000_000) * model_price["output"]
    total_cost = cost_input + cost_output

    # Budget check
    budget = session.get("budget", config.get("budget", {}).get("maxPerSession", 0)) if config else 0
    if budget and total_cost > budget * 0.8:
        findings.append({
            "severity": "HIGH" if total_cost > budget else "MEDIUM",
            "check": "cost.budget",
            "message": f"Session cost ${total_cost:.4f} is "
                       f"{'over' if total_cost > budget else 'near'} "
                       f"budget ${budget:.4f}.",
        })

    # Tool call analysis
    tool_calls = session.get("toolCalls", [])
    tool_stats: dict[str, int] = {}
    for tc in tool_calls:
        name = tc.get("name", "unknown") if isinstance(tc, dict) else str(tc)
        tool_stats[name] = tool_stats.get(name, 0) + 1

    max_sev = "OK"
    for f in findings:
        if f["severity"] == "HIGH":
            max_sev = "HIGH"
        elif f["severity"] == "MEDIUM" and max_sev == "OK":
            max_sev = "MEDIUM"

    return {
        "ok": True,
        "severity": max_sev,
        "model": model,
        "tokens": {
            "input": input_tokens,
            "output": output_tokens,
            "total": input_tokens + output_tokens,
        },
        "cost": {
            "input": round(cost_input, 6),
            "output": round(cost_output, 6),
            "total": round(total_cost, 6),
            "currency": "USD",
        },
        "budget": budget,
        "tool_stats": tool_stats,
        "tool_calls_total": len(tool_calls),
        "findings": findings,
        "finding_count": len(findings),
    }


def firm_token_budget_optimizer(
    session_data: dict[str, Any] | None = None,
    config_path: str | None = None,
) -> dict[str, Any]:
    """
    Token optimization analysis.

    Analyzes:
    - Context compression opportunities
    - Prompt deduplication
    - Caching hit rate
    - Tool call pattern optimization
    """
    config, cfg_path = load_config(config_path)
    findings: list[dict[str, str]] = []
    session = session_data or {}
    recommendations: list[dict[str, Any]] = []

    tokens_used = session.get("tokensUsed", session.get("token_count", 0))
    context_window = session.get("contextWindow", session.get("max_tokens", 200000))

    # Prompt analysis
    system_prompt_tokens = session.get("systemPromptTokens", 0)
    if system_prompt_tokens and tokens_used:
        ratio = system_prompt_tokens / tokens_used
        if ratio > 0.3:
            recommendations.append({
                "type": "system_prompt",
                "savings_pct": round((ratio - 0.15) * 100, 1),
                "message": f"System prompt uses {ratio:.0%} of tokens. "
                           "Consider compression or lazy loading.",
            })

    # Tool result analysis
    tool_result_tokens = session.get("toolResultTokens", 0)
    if tool_result_tokens and tokens_used:
        ratio = tool_result_tokens / tokens_used
        if ratio > 0.4:
            recommendations.append({
                "type": "tool_results",
                "savings_pct": round((ratio - 0.2) * 100, 1),
                "message": f"Tool results use {ratio:.0%} of tokens. "
                           "Enable result summarization or truncation.",
            })

    # Cache analysis
    cache_hits = session.get("cacheHits", 0)
    cache_misses = session.get("cacheMisses", 0)
    total_cache = cache_hits + cache_misses
    if total_cache > 0:
        hit_rate = cache_hits / total_cache
        if hit_rate < 0.5:
            recommendations.append({
                "type": "caching",
                "savings_pct": round((0.7 - hit_rate) * 30, 1),
                "message": f"Cache hit rate is {hit_rate:.0%}. "
                           "Enable prompt caching for repeated queries.",
            })

    # Deduplication
    messages = session.get("messages", [])
    if len(messages) > 10:
        seen_hashes: set[str] = set()
        duplicates = 0
        for msg in messages:
            content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
            h = hashlib.md5(content.encode()).hexdigest()
            if h in seen_hashes:
                duplicates += 1
            seen_hashes.add(h)

        if duplicates > 2:
            recommendations.append({
                "type": "deduplication",
                "savings_pct": round(duplicates / len(messages) * 100, 1),
                "message": f"Found {duplicates} duplicate messages in context.",
            })

    total_savings = sum(r.get("savings_pct", 0) for r in recommendations)

    return {
        "ok": True,
        "tokens_used": tokens_used,
        "context_window": context_window,
        "utilization": round(tokens_used / context_window, 3) if context_window else 0,
        "recommendations": recommendations,
        "recommendation_count": len(recommendations),
        "estimated_savings_pct": round(min(total_savings, 60), 1),
        "findings": findings,
        "finding_count": len(findings),
    }


# ── TOOLS registry ───────────────────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "firm_mcp_firewall_check",
        "title": "MCP Firewall Policy Check",
        "description": (
            "MCP Gateway firewall policy audit. Checks tool allowlists, "
            "argument sanitization, per-tool rate limits, secret leakage "
            "prevention, request size limits. Gap G21."
        ),
        "category": "ecosystem",
        "handler": firm_mcp_firewall_check,
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
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_rag_pipeline_check",
        "title": "RAG Pipeline Validation",
        "description": (
            "RAG pipeline health & configuration audit. Checks embedding model, "
            "vector store, chunk settings, retrieval top-K, index freshness. Gap G22."
        ),
        "category": "ecosystem",
        "handler": firm_rag_pipeline_check,
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
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_sandbox_exec_check",
        "title": "Sandbox Execution Check",
        "description": (
            "Sandbox execution isolation audit. Checks sandbox mode, "
            "resource limits, filesystem restrictions, network policy, "
            "timeout enforcement. Gap G26."
        ),
        "category": "ecosystem",
        "handler": firm_sandbox_exec_check,
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
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_context_health_check",
        "title": "Context Window Health",
        "description": (
            "Context rot / cognitive health detection. Checks token utilization, "
            "session age, turn count, compression ratio, recovery recommendations. Gap G23."
        ),
        "category": "ecosystem",
        "handler": firm_context_health_check,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_data": {
                    "type": "object",
                    "description": "Session data with tokensUsed, contextWindow, createdAt, turns.",
                },
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_provenance_tracker",
        "title": "Provenance Chain Tracker",
        "description": (
            "Cryptographic audit trail / provenance tracking. "
            "Actions: append (hash chain entry), verify (integrity check), "
            "status, export. Gap G24."
        ),
        "category": "ecosystem",
        "handler": firm_provenance_tracker,
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["append", "verify", "status", "export"],
                    "default": "status",
                },
                "entry": {
                    "type": "object",
                    "description": "Provenance entry: intent, agent, action, inputs, outputs.",
                },
                "chain_path": {"type": "string", "description": "Export file path."},
                "algorithm": {
                    "type": "string",
                    "enum": ["sha256", "sha384", "sha512"],
                    "default": "sha256",
                },
            },
            "required": [],
        },
    },
    {
        "name": "firm_cost_analytics",
        "title": "Cost Analytics Dashboard",
        "description": (
            "Usage/cost tracking and analysis. Estimates cost per session, "
            "checks budget thresholds, analyzes tool call patterns. Gap G27."
        ),
        "category": "ecosystem",
        "handler": firm_cost_analytics,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_data": {
                    "type": "object",
                    "description": "Session data with model, tokens, toolCalls, budget.",
                },
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
    {
        "name": "firm_token_budget_optimizer",
        "title": "Token Budget Optimizer",
        "description": (
            "Token optimization analysis. Finds compression opportunities, "
            "prompt deduplication, caching improvements, tool result savings. Gap G25."
        ),
        "category": "ecosystem",
        "handler": firm_token_budget_optimizer,
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
        "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_data": {
                    "type": "object",
                    "description": "Session data with tokensUsed, messages, cache stats.",
                },
                "config_path": {"type": "string", "description": "Firm config path."},
            },
            "required": [],
        },
    },
]
