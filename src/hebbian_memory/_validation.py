"""
Validation tools: layer_validate, pii_check, decay_config_check, drift_check.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ._helpers import (
    _DEFAULT_DECAY,
    _DEFAULT_LEARNING_RATE,
    _PII_PATTERNS,
    _THRESHOLD_EPISODIC_TO_EMERGENT,
    _THRESHOLD_EMERGENT_TO_STRONG,
    _WEIGHT_MAX,
    _WEIGHT_MIN,
    _cosine_similarity,
    _detect_layers,
    _extract_layer2_rules,
    _tokenize,
    get_nested,
    load_config,
)

logger = logging.getLogger(__name__)


async def openclaw_hebbian_layer_validate(
    claude_md_path: str,
) -> dict[str, Any]:
    """Validate the 4-layer structure of a Hebbian-augmented Claude.md."""
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"File not found: {claude_md_path}"}

    content = md_path.read_text(encoding="utf-8")
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    layers = _detect_layers(content)

    for layer_num, label in [
        (1, "CORE (immuable)"), (2, "CONSOLIDATED PATTERNS"),
        (3, "EPISODIC INDEX"), (4, "META INSTRUCTIONS"),
    ]:
        if not layers.get(layer_num):
            findings.append({
                "severity": "HIGH", "layer": layer_num,
                "message": f"Layer {layer_num} — {label} is missing.",
            })
            recommendations.append(f"Add Layer {layer_num} ({label}) section per CDC §3.3.")

    if layers.get(2):
        rules = _extract_layer2_rules(content)
        if not rules:
            findings.append({
                "severity": "MEDIUM", "layer": 2,
                "message": "Layer 2 exists but contains no weighted rules [0.XX].",
            })
        else:
            for rule in rules:
                if rule["weight"] > _WEIGHT_MAX:
                    findings.append({
                        "severity": "HIGH", "layer": 2,
                        "message": f"Rule '{rule['rule_id']}' has weight {rule['weight']} > max {_WEIGHT_MAX}.",
                    })
                if rule["weight"] < _WEIGHT_MIN:
                    findings.append({
                        "severity": "MEDIUM", "layer": 2,
                        "message": f"Rule '{rule['rule_id']}' has negative weight {rule['weight']}.",
                    })

    for label, pattern in _PII_PATTERNS:
        if pattern.search(content):
            findings.append({
                "severity": "CRITICAL", "layer": 0,
                "message": f"Potential PII detected ({label}) in Claude.md content.",
            })

    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    elif not all(layers.values()):
        status = "incomplete"
    else:
        status = "ok"

    return {
        "ok": True, "status": status, "layers_found": layers,
        "findings": findings, "recommendations": recommendations,
        "total_rules": len(_extract_layer2_rules(content)),
    }


async def openclaw_hebbian_pii_check(
    config_path: str | None = None,
    config_data: dict | None = None,
) -> dict[str, Any]:
    """Audit PII stripping configuration for Hebbian memory storage."""
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    if config_data is not None:
        cfg = config_data
    elif config_path:
        cfg, _ = load_config(config_path)
    else:
        return {"ok": False, "error": "No config_path or config_data provided."}

    hebbian = get_nested(cfg, "hebbian", default={})
    if not hebbian:
        hebbian = get_nested(cfg, "memory", "hebbian", default={})

    if not hebbian:
        return {
            "ok": True, "status": "info",
            "message": "No 'hebbian' section found in config.",
            "findings": [],
            "recommendations": ["Add a 'hebbian' section with PII stripping config per CDC §5.2."],
        }

    pii_config = get_nested(hebbian, "pii_stripping", default={})
    security = get_nested(hebbian, "security", default={})

    expected_patterns = {"email", "phone", "ip", "api_key", "ssn"}
    configured_patterns = set(pii_config.get("patterns", []))

    if not configured_patterns:
        findings.append({
            "severity": "CRITICAL",
            "message": "No PII stripping patterns configured. All stored data may contain PII.",
        })
        recommendations.append("Configure pii_stripping.patterns with at least: email, phone, ip, api_key.")
    else:
        missing = expected_patterns - configured_patterns
        if missing:
            findings.append({
                "severity": "HIGH",
                "message": f"Missing PII patterns: {sorted(missing)}. These types won't be stripped.",
            })
            recommendations.append(f"Add missing patterns: {sorted(missing)}")

    if not pii_config.get("enabled", False):
        findings.append({
            "severity": "CRITICAL",
            "message": "PII stripping is disabled. Embeddings may contain sensitive data.",
        })

    if not security.get("secret_detection", False):
        findings.append({
            "severity": "HIGH",
            "message": "Secret detection is not enabled. API keys/tokens may leak into embeddings.",
        })
        recommendations.append("Enable security.secret_detection per CDC §5.2.")

    if not security.get("embedding_rotation"):
        findings.append({
            "severity": "MEDIUM",
            "message": "No embedding rotation policy defined.",
        })
        recommendations.append("Define security.embedding_rotation policy for breach response.")

    access = security.get("access_restriction")
    if not access or access not in ("localhost", "vpn", "private_network"):
        findings.append({
            "severity": "HIGH",
            "message": "Database access not restricted to localhost/VPN.",
        })
        recommendations.append("Set security.access_restriction to 'localhost' or 'vpn'.")

    if not pii_config.get("ner_model"):
        recommendations.append("Consider adding a NER model for improved PII detection (optional).")

    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    else:
        status = "ok"

    return {
        "ok": True, "status": status,
        "findings": findings, "recommendations": recommendations,
    }


async def openclaw_hebbian_decay_config_check(
    config_path: str | None = None,
    config_data: dict | None = None,
) -> dict[str, Any]:
    """Validate Hebbian learning rate, decay, and consolidation thresholds."""
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    if config_data is not None:
        cfg = config_data
    elif config_path:
        cfg, _ = load_config(config_path)
    else:
        return {"ok": False, "error": "No config_path or config_data provided."}

    hebbian = get_nested(cfg, "hebbian", default={})
    if not hebbian:
        hebbian = get_nested(cfg, "memory", "hebbian", default={})

    if not hebbian:
        return {
            "ok": True, "status": "info",
            "message": "No 'hebbian' section found in config.",
            "findings": [],
            "recommendations": ["Add a 'hebbian' section with Hebbian parameters per CDC §4.3."],
        }

    params = get_nested(hebbian, "parameters", default={})

    lr = params.get("learning_rate", _DEFAULT_LEARNING_RATE)
    if not (0.001 <= lr <= 0.5):
        findings.append({
            "severity": "CRITICAL",
            "message": f"learning_rate={lr} is outside safe range [0.001, 0.5].",
        })

    decay_val = params.get("decay", _DEFAULT_DECAY)
    if not (0.001 <= decay_val <= 0.2):
        findings.append({
            "severity": "CRITICAL",
            "message": f"decay={decay_val} is outside safe range [0.001, 0.2].",
        })

    poids_max = params.get("poids_max", _WEIGHT_MAX)
    if poids_max > 0.95:
        findings.append({
            "severity": "HIGH",
            "message": f"poids_max={poids_max} exceeds CDC limit of 0.95.",
        })

    poids_min = params.get("poids_min", _WEIGHT_MIN)
    if poids_min < 0.0:
        findings.append({
            "severity": "MEDIUM",
            "message": f"poids_min={poids_min} is negative. Weights should floor at 0.0.",
        })

    thresholds = get_nested(hebbian, "thresholds", default={})
    episodic = thresholds.get("episodic_to_emergent", _THRESHOLD_EPISODIC_TO_EMERGENT)
    if episodic < 3:
        findings.append({
            "severity": "MEDIUM",
            "message": f"episodic_to_emergent={episodic} is too low. Minimum 3 sessions recommended.",
        })

    emergent_weight = thresholds.get("emergent_to_strong", _THRESHOLD_EMERGENT_TO_STRONG)
    if emergent_weight < 0.5:
        findings.append({
            "severity": "MEDIUM",
            "message": f"emergent_to_strong threshold={emergent_weight} is too permissive.",
        })

    max_auto = get_nested(hebbian, "anti_drift", "max_consecutive_auto_changes", default=3)
    if max_auto > 5:
        findings.append({
            "severity": "HIGH",
            "message": f"max_consecutive_auto_changes={max_auto} is too high. CDC §5.1 recommends max 3.",
        })

    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        status = "critical"
    elif "HIGH" in severities:
        status = "high"
    elif "MEDIUM" in severities:
        status = "medium"
    else:
        status = "ok"

    return {
        "ok": True, "status": status,
        "parameters": {"learning_rate": lr, "decay": decay_val, "poids_min": poids_min, "poids_max": poids_max},
        "thresholds": {"episodic_to_emergent": episodic, "emergent_to_strong": emergent_weight},
        "findings": findings, "recommendations": recommendations,
    }


async def openclaw_hebbian_drift_check(
    claude_md_path: str,
    baseline_path: str | None = None,
    threshold: float = 0.7,
) -> dict[str, Any]:
    """Compare Claude.md against a baseline to detect semantic drift."""
    md_path = Path(claude_md_path)
    if not md_path.exists():
        return {"ok": False, "error": f"Current Claude.md not found: {claude_md_path}"}

    if baseline_path:
        base_path = Path(baseline_path)
    else:
        base_path = md_path.parent / "claude-md-baseline.md"

    if not base_path.exists():
        return {
            "ok": True, "status": "no_baseline",
            "message": f"No baseline found at {base_path}. Create one with: cp {claude_md_path} {base_path}",
            "similarity": None, "drift_detected": None,
        }

    current = md_path.read_text(encoding="utf-8")
    baseline = base_path.read_text(encoding="utf-8")

    similarity = _cosine_similarity(current, baseline)
    similarity = round(similarity, 4)
    drift_detected = similarity < threshold

    findings: list[dict[str, str]] = []
    if drift_detected:
        severity = "CRITICAL" if similarity < 0.4 else "HIGH"
        findings.append({
            "severity": severity,
            "message": (
                f"Semantic drift detected: similarity={similarity} < threshold={threshold}. "
                "Claude.md has diverged significantly from baseline."
            ),
        })

    if drift_detected and similarity < 0.4:
        status = "critical"
    elif drift_detected:
        status = "high"
    else:
        status = "ok"

    return {
        "ok": True, "status": status,
        "similarity": similarity, "threshold": threshold,
        "drift_detected": drift_detected, "findings": findings,
        "current_tokens": len(_tokenize(current)),
        "baseline_tokens": len(_tokenize(baseline)),
    }
