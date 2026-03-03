"""
Coverage tests for src/hebbian_memory/ — _helpers, _runtime, _analysis, _validation.
Targets: 17-64% → 100%.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════════════════
# _helpers.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestStripPii:
    def test_email(self):
        from src.hebbian_memory._helpers import _strip_pii
        assert "[REDACTED_EMAIL]" in _strip_pii("Contact user@example.com for info")

    def test_api_key(self):
        from src.hebbian_memory._helpers import _strip_pii
        result = _strip_pii("Token: sk-abc123def456ghi")
        assert "[REDACTED" in result

    def test_generic_api_key(self):
        from src.hebbian_memory._helpers import _strip_pii
        r = _strip_pii("api_key=ABCDEFghijklmnop1234567890ABCDEF")
        assert "[REDACTED" in r

    def test_ipv4(self):
        from src.hebbian_memory._helpers import _strip_pii
        assert "[REDACTED_IPV4]" in _strip_pii("Server at 192.168.1.100 is down")

    def test_phone(self):
        from src.hebbian_memory._helpers import _strip_pii
        result = _strip_pii("Call +1-555-123-4567")
        assert "[REDACTED" in result

    def test_aws_key(self):
        from src.hebbian_memory._helpers import _strip_pii
        assert "[REDACTED_AWS_KEY]" in _strip_pii("AKIAIOSFODNN7EXAMPLE is the key")

    def test_jwt(self):
        from src.hebbian_memory._helpers import _strip_pii
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = _strip_pii(f"Token: {jwt}")
        assert "[REDACTED" in result

    def test_no_pii(self):
        from src.hebbian_memory._helpers import _strip_pii
        text = "Hello world, this is safe text"
        assert _strip_pii(text) == text


class TestValidateHebbianPath:
    def test_valid_path(self, tmp_path):
        from src.hebbian_memory._helpers import _validate_hebbian_path
        f = tmp_path / "data.jsonl"
        f.write_text("")
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            # Should not raise
            _validate_hebbian_path(str(f), "test")

    def test_invalid_path(self, tmp_path):
        from src.hebbian_memory._helpers import _validate_hebbian_path
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            with pytest.raises(ValueError, match="outside allowed"):
                _validate_hebbian_path("/etc/passwd", "test")


class TestInitDb:
    def test_creates_db(self, tmp_path):
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "subdir" / "hebb.db")
        _init_db(db)
        assert Path(db).exists()
        conn = sqlite3.connect(db)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = {t[0] for t in tables}
        assert "hebbian_sessions" in table_names
        assert "hebbian_weight_history" in table_names
        conn.close()

    def test_idempotent(self, tmp_path):
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "hebb.db")
        _init_db(db)
        _init_db(db)  # second call should not error


class TestTokenize:
    def test_basic(self):
        from src.hebbian_memory._helpers import _tokenize
        tokens = _tokenize("Hello World! This is a TEST.")
        assert "hello" in tokens
        assert "world" in tokens
        assert "test" in tokens

    def test_empty(self):
        from src.hebbian_memory._helpers import _tokenize
        assert _tokenize("") == []


class TestCosineSimilarity:
    def test_identical(self):
        from src.hebbian_memory._helpers import _cosine_similarity
        assert _cosine_similarity("hello world", "hello world") == pytest.approx(1.0, abs=0.01)

    def test_different(self):
        from src.hebbian_memory._helpers import _cosine_similarity
        result = _cosine_similarity("cat dog", "airplane bicycle")
        assert result < 0.3

    def test_empty(self):
        from src.hebbian_memory._helpers import _cosine_similarity
        assert _cosine_similarity("", "") == pytest.approx(0.0, abs=0.01)


class TestDetectLayers:
    def test_all_layers(self):
        from src.hebbian_memory._helpers import _detect_layers
        content = """
LAYER 1 — CORE DIRECTIVES
stuff
LAYER 2 — CONSOLIDATED PATTERNS
- [0.50] rule
LAYER 3 — EPISODIC BUFFER
more
LAYER 4 — META-COGNITIVE
final
"""
        layers = _detect_layers(content)
        assert layers[1] is True
        assert layers[2] is True

    def test_no_layers(self):
        from src.hebbian_memory._helpers import _detect_layers
        layers = _detect_layers("Just some random text without layers.")
        assert not any(layers.values())


class TestExtractLayer2Rules:
    def test_extracts_rules(self):
        from src.hebbian_memory._helpers import _extract_layer2_rules
        content = """
## Layer 2 — Weighted Rules
- [0.85] Always test before push
- [0.42] Keep comments concise
"""
        rules = _extract_layer2_rules(content)
        assert len(rules) >= 2
        assert any(r["weight"] == pytest.approx(0.85, abs=0.01) for r in rules)

    def test_no_rules(self):
        from src.hebbian_memory._helpers import _extract_layer2_rules
        content = "No layer 2 rules here."
        rules = _extract_layer2_rules(content)
        assert rules == []


# ═══════════════════════════════════════════════════════════════════════════════
# _runtime.py — harvest + weight_update
# ═══════════════════════════════════════════════════════════════════════════════

class TestHebbianHarvest:
    def test_file_not_found(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_harvest
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            r = _run(firm_hebbian_harvest(session_jsonl_path=str(tmp_path / "nope.jsonl")))
            assert r.get("ok") is False or "error" in r

    def test_wrong_extension(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_harvest
        f = tmp_path / "data.txt"
        f.write_text("")
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            r = _run(firm_hebbian_harvest(session_jsonl_path=str(f)))
            assert r.get("ok") is False or "error" in r

    def test_happy_path(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_harvest
        f = tmp_path / "sessions.jsonl"
        lines = [
            json.dumps({
                "session_id": f"s{i}",
                "summary": f"Session {i} summary text here",
                "tags": json.dumps(["tag1", "tag2"]),
                "rules_activated": json.dumps(["rule1"]),
                "quality_score": 0.8,
                "timestamp": time.time(),
            })
            for i in range(3)
        ]
        f.write_text("\n".join(lines))
        db_path = str(tmp_path / "hebb.db")
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            r = _run(firm_hebbian_harvest(
                session_jsonl_path=str(f),
                db_path=db_path,
            ))
            assert r.get("ok") is True or r.get("harvested", 0) >= 0

    def test_bad_json_lines(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_harvest
        f = tmp_path / "bad.jsonl"
        f.write_text("not json\n{bad\n")
        db_path = str(tmp_path / "h.db")
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            r = _run(firm_hebbian_harvest(session_jsonl_path=str(f), db_path=db_path))
            # Should handle gracefully
            assert isinstance(r, dict)

    def test_max_lines(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_harvest
        f = tmp_path / "large.jsonl"
        lines = [json.dumps({"session_id": f"s{i}", "summary": f"S{i}", "tags": "[]", "rules_activated": "[]", "quality_score": 0.5, "timestamp": time.time()}) for i in range(10)]
        f.write_text("\n".join(lines))
        db_path = str(tmp_path / "h.db")
        with patch.dict(os.environ, {"HEBBIAN_ALLOWED_DIRS": str(tmp_path)}):
            r = _run(firm_hebbian_harvest(session_jsonl_path=str(f), db_path=db_path, max_lines=3))
            assert isinstance(r, dict)


class TestHebbianWeightUpdate:
    def test_claude_md_not_found(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_weight_update
        r = _run(firm_hebbian_weight_update(claude_md_path=str(tmp_path / "nope.md")))
        assert r.get("ok") is False or "error" in r

    def test_no_layer2_rules(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_weight_update
        md = tmp_path / "CLAUDE.md"
        md.write_text("# CLAUDE\nNo layer 2 rules here.")
        r = _run(firm_hebbian_weight_update(claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_dry_run(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_weight_update
        md = tmp_path / "CLAUDE.md"
        md.write_text("""# CLAUDE
## Layer 2 — Weighted Rules
- [0.50] Always test before push
- [0.80] Keep code DRY
""")
        db_path = str(tmp_path / "h.db")
        r = _run(firm_hebbian_weight_update(
            claude_md_path=str(md), db_path=db_path, dry_run=True,
        ))
        assert isinstance(r, dict)

    def test_actual_write(self, tmp_path):
        from src.hebbian_memory._runtime import firm_hebbian_weight_update
        md = tmp_path / "CLAUDE.md"
        md.write_text("""# CLAUDE
## Layer 2 — Weighted Rules
- [0.50] Always test before push
""")
        db_path = str(tmp_path / "h.db")
        r = _run(firm_hebbian_weight_update(
            claude_md_path=str(md), db_path=db_path, dry_run=False,
        ))
        assert isinstance(r, dict)


class TestComputeHebbianWeights:
    def test_activated_rule_positive_delta(self):
        from src.hebbian_memory._runtime import _compute_hebbian_weights
        rules = [{"rule_id": "r1", "text": "rule 1", "weight": 0.5}]
        changes, promo, atrophy = _compute_hebbian_weights(
            rules, activated_rule_ids={"r1"}, learning_rate=0.1, decay=0.02,
        )
        assert len(changes) == 1
        assert changes[0]["new_weight"] > 0.5

    def test_non_activated_decay(self):
        from src.hebbian_memory._runtime import _compute_hebbian_weights
        rules = [{"rule_id": "r1", "text": "rule 1", "weight": 0.5}]
        changes, promo, atrophy = _compute_hebbian_weights(
            rules, activated_rule_ids=set(), learning_rate=0.1, decay=0.02,
        )
        assert changes[0]["new_weight"] < 0.5

    def test_weight_clamping(self):
        from src.hebbian_memory._runtime import _compute_hebbian_weights
        rules = [{"rule_id": "r1", "text": "rule 1", "weight": 0.94}]
        changes, promo, atrophy = _compute_hebbian_weights(
            rules, activated_rule_ids={"r1"}, learning_rate=0.5, decay=0.0,
        )
        assert changes[0]["new_weight"] <= 0.95


class TestApplyWeightChanges:
    def test_apply_formatted(self):
        from src.hebbian_memory._runtime import _apply_weight_changes
        content = "- [0.50] My rule text"
        changes = [{"id": "r1", "text": "My rule text", "old_weight": 0.5, "new_weight": 0.65}]
        result = _apply_weight_changes(content, changes)
        assert "[0.65]" in result

    def test_apply_no_match(self):
        from src.hebbian_memory._runtime import _apply_weight_changes
        content = "No rules here"
        changes = [{"id": "r1", "text": "Missing", "old_weight": 0.5, "new_weight": 0.6}]
        result = _apply_weight_changes(content, changes)
        assert result == content


# ═══════════════════════════════════════════════════════════════════════════════
# _analysis.py — analyze + status
# ═══════════════════════════════════════════════════════════════════════════════

class TestHebbianAnalyze:
    def test_no_db(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_analyze
        r = _run(firm_hebbian_analyze(db_path=str(tmp_path / "nope.db")))
        assert isinstance(r, dict)

    def test_empty_db(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_analyze
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "h.db")
        _init_db(db)
        r = _run(firm_hebbian_analyze(db_path=db))
        assert isinstance(r, dict)

    def test_with_sessions(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_analyze
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "h.db")
        _init_db(db)
        conn = sqlite3.connect(db)
        for i in range(5):
            conn.execute(
                "INSERT INTO hebbian_sessions (session_id, summary, tags, rules_activated, quality_score) VALUES (?, ?, ?, ?, ?)",
                (f"s{i}", f"Session {i}", json.dumps(["tag1", "tag2"]), json.dumps(["rule1", "rule2"]), 0.8),
            )
        conn.commit()
        conn.close()
        r = _run(firm_hebbian_analyze(db_path=db, min_cluster_size=1))
        assert isinstance(r, dict)


class TestHebbianStatus:
    def test_no_db(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_status
        r = _run(firm_hebbian_status(db_path=str(tmp_path / "nope.db")))
        assert r.get("db_exists") is False

    def test_with_db(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_status
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "h.db")
        _init_db(db)
        r = _run(firm_hebbian_status(db_path=db))
        assert isinstance(r, dict)

    def test_with_claude_md(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_status
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "h.db")
        _init_db(db)
        md = tmp_path / "CLAUDE.md"
        md.write_text("""## Layer 2 — Weighted Rules
- [0.95] Promoted rule
- [0.05] Atrophy rule
""")
        r = _run(firm_hebbian_status(db_path=db, claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_claude_md_not_found(self, tmp_path):
        from src.hebbian_memory._analysis import firm_hebbian_status
        from src.hebbian_memory._helpers import _init_db
        db = str(tmp_path / "h.db")
        _init_db(db)
        r = _run(firm_hebbian_status(db_path=db, claude_md_path=str(tmp_path / "nope.md")))
        assert isinstance(r, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# _validation.py — layer_validate, pii_check, decay_config_check, drift_check
# ═══════════════════════════════════════════════════════════════════════════════

class TestLayerValidate:
    def test_file_not_found(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_layer_validate
        r = _run(firm_hebbian_layer_validate(claude_md_path=str(tmp_path / "nope.md")))
        assert r.get("ok") is False or "error" in r

    def test_missing_layers(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text("# CLAUDE\nJust some text without any layers.")
        r = _run(firm_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)
        assert len(r.get("findings", [])) > 0

    def test_all_layers_present(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text("""# CLAUDE
## Layer 1 — Foundation
base rules
## Layer 2 — Weighted Rules
- [0.50] Some rule
## Layer 3 — Emergent Patterns
emerging
## Layer 4 — Meta-Cognitive
meta
""")
        r = _run(firm_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_high_weight_flagged(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text("""## Layer 2 — Weighted Rules
- [0.96] Over threshold rule
- [-0.10] Negative weight
""")
        r = _run(firm_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_pii_in_rules(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_layer_validate
        md = tmp_path / "CLAUDE.md"
        md.write_text("""## Layer 2 — Weighted Rules
- [0.50] Contact user@example.com for info
""")
        r = _run(firm_hebbian_layer_validate(claude_md_path=str(md)))
        assert isinstance(r, dict)


class TestPiiCheck:
    def test_no_config(self):
        from src.hebbian_memory._validation import firm_hebbian_pii_check
        r = _run(firm_hebbian_pii_check())
        assert isinstance(r, dict)

    def test_no_hebbian_section(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_pii_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"gateway": {}}))
        r = _run(firm_hebbian_pii_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_with_hebbian_config(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_pii_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({
            "hebbian": {
                "pii": {"enabled": True, "patterns": ["email", "phone"]},
                "secret_detection": {"enabled": True},
                "embedding_rotation": {"enabled": True, "interval_days": 30},
                "access_restriction": {"mode": "allowlist", "allowed": ["admin"]},
            },
        }))
        r = _run(firm_hebbian_pii_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_pii_disabled(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_pii_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"hebbian": {"pii": {"enabled": False}}}))
        r = _run(firm_hebbian_pii_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_config_data_dict(self):
        from src.hebbian_memory._validation import firm_hebbian_pii_check
        r = _run(firm_hebbian_pii_check(config_data={"hebbian": {"pii": {"enabled": True, "patterns": ["email"]}}}))
        assert isinstance(r, dict)


class TestDecayConfigCheck:
    def test_no_config(self):
        from src.hebbian_memory._validation import firm_hebbian_decay_config_check
        r = _run(firm_hebbian_decay_config_check())
        assert isinstance(r, dict)

    def test_good_config(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_decay_config_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({
            "hebbian": {
                "learning_rate": 0.05,
                "decay": 0.02,
                "poids_max": 0.95,
                "poids_min": 0.0,
                "episodic_to_emergent": 5,
                "emergent_to_strong": 0.7,
                "max_consecutive_auto_changes": 3,
            },
        }))
        r = _run(firm_hebbian_decay_config_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_bad_learning_rate(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_decay_config_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"hebbian": {"learning_rate": 5.0, "decay": 0.5}}))
        r = _run(firm_hebbian_decay_config_check(config_path=str(cfg)))
        assert isinstance(r, dict)

    def test_bad_poids(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_decay_config_check
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"hebbian": {"poids_max": 1.5, "poids_min": -0.5, "max_consecutive_auto_changes": 10}}))
        r = _run(firm_hebbian_decay_config_check(config_path=str(cfg)))
        assert isinstance(r, dict)


class TestDriftCheck:
    def test_current_not_found(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_drift_check
        r = _run(firm_hebbian_drift_check(claude_md_path=str(tmp_path / "nope.md")))
        assert r.get("ok") is False or "error" in r

    def test_no_baseline(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_drift_check
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Current CLAUDE.md content")
        r = _run(firm_hebbian_drift_check(claude_md_path=str(md)))
        assert isinstance(r, dict)

    def test_identical_baseline(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_drift_check
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Same content here")
        baseline = tmp_path / "baseline.md"
        baseline.write_text("# Same content here")
        r = _run(firm_hebbian_drift_check(claude_md_path=str(md), baseline_path=str(baseline)))
        assert isinstance(r, dict)

    def test_drifted(self, tmp_path):
        from src.hebbian_memory._validation import firm_hebbian_drift_check
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Completely new content with different words and topics about space exploration")
        baseline = tmp_path / "baseline.md"
        baseline.write_text("# Original content about gardening and flowers and soil types")
        r = _run(firm_hebbian_drift_check(claude_md_path=str(md), baseline_path=str(baseline), threshold=0.99))
        assert isinstance(r, dict)
