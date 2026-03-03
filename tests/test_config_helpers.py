"""
Unit tests for src/config_helpers.py — shared DRY helpers.
"""

from __future__ import annotations

import json

import pytest

from src.config_helpers import load_config, get_nested, mask_secret, check_ssrf, no_path_traversal


class TestLoadConfig:
    def test_load_valid_json(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"gateway": {"port": 3000}}))
        data, path = load_config(str(cfg))
        assert data["gateway"]["port"] == 3000
        assert path == str(cfg.resolve())

    def test_load_missing_file(self):
        data, path = load_config("/nonexistent/config.json")
        assert data == {}

    def test_load_invalid_json(self, tmp_path):
        cfg = tmp_path / "bad.json"
        cfg.write_text("not json {{{")
        with pytest.raises(Exception):
            load_config(str(cfg))


class TestGetNested:
    def test_simple_key(self):
        assert get_nested({"a": 1}, "a") == 1

    def test_nested_keys(self):
        data = {"a": {"b": {"c": 42}}}
        assert get_nested(data, "a", "b", "c") == 42

    def test_missing_key_default(self):
        assert get_nested({"a": 1}, "b", default="nope") == "nope"

    def test_deep_missing(self):
        assert get_nested({"a": {"b": 1}}, "a", "c", "d", default=None) is None


class TestMaskSecret:
    def test_mask_long_secret(self):
        result = mask_secret("sk-test-secret-key-12345678")
        assert result.endswith("5678")
        assert result.startswith("****")

    def test_mask_short_secret(self):
        result = mask_secret("abc")
        assert "****" in result

    def test_mask_none(self):
        result = mask_secret(None)
        assert result == "****"


class TestCheckSsrf:
    def test_localhost_blocked(self):
        err = check_ssrf("http://localhost:8080/api")
        assert err is not None
        assert "blocked" in err.lower() or "ssrf" in err.lower()

    def test_127_blocked(self):
        err = check_ssrf("http://127.0.0.1:3000/mcp")
        assert err is not None

    def test_private_range_blocked(self):
        err = check_ssrf("http://192.168.1.1/api")
        assert err is not None

    def test_ipv6_loopback_blocked(self):
        err = check_ssrf("http://[::1]:8080/api")
        assert err is not None

    def test_public_url_allowed(self):
        err = check_ssrf("https://api.example.com/v1")
        assert err is None

    def test_0000_blocked(self):
        err = check_ssrf("http://0.0.0.0:8080/api")
        assert err is not None


class TestNoPathTraversal:
    def test_clean_path(self):
        result = no_path_traversal("/var/config/openclaw.json")
        assert result is None

    def test_dotdot_blocked(self):
        result = no_path_traversal("/etc/../passwd")
        assert result is not None

    def test_url_encoded_blocked(self):
        result = no_path_traversal("/etc/%2e%2e/passwd")
        assert result is not None

    def test_double_encoded_blocked(self):
        result = no_path_traversal("/etc/%252e%252e/passwd")
        assert result is not None
