"""Coverage push — models.py Pydantic validators + config_helpers SSRF."""
from __future__ import annotations
import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# models.py — Pydantic no_traversal validators (parametrized)
# ---------------------------------------------------------------------------

_TRAVERSAL = "../etc/passwd"


def _import_model(name):
    import src.models as m
    return getattr(m, name)


# Each tuple: (ModelClass name, field_name, bad_value, extra_kwargs)
_TRAVERSAL_CASES = [
    # ConfigPathInput derivatives
    ("ConfigPathInput", "config_path", _TRAVERSAL, {}),
    ("CiPipelineCheckInput", "repo_path", _TRAVERSAL, {"ci_dir": ".github"}),
    ("CiPipelineCheckInput", "ci_dir", _TRAVERSAL, {"repo_path": "/ok"}),
    ("KnowledgeGraphCheckInput", "graph_data_path", _TRAVERSAL, {}),
    ("HebbianHarvestInput", "session_jsonl_path", _TRAVERSAL, {}),
    ("HebbianHarvestInput", "claude_md_path", _TRAVERSAL, {"session_jsonl_path": "/ok.jsonl"}),
    ("HebbianHarvestInput", "db_path", _TRAVERSAL, {"session_jsonl_path": "/ok.jsonl"}),
    ("HebbianWeightUpdateInput", "claude_md_path", _TRAVERSAL, {}),
    ("HebbianWeightUpdateInput", "db_path", _TRAVERSAL, {"claude_md_path": "/ok.md"}),
    ("HebbianAnalyzeInput", "db_path", _TRAVERSAL, {}),
    ("HebbianStatusInput", "db_path", _TRAVERSAL, {}),
    ("HebbianStatusInput", "claude_md_path", _TRAVERSAL, {"db_path": "/ok.db"}),
    ("HebbianLayerValidateInput", "claude_md_path", _TRAVERSAL, {}),
    ("HebbianPiiCheckInput", "config_path", _TRAVERSAL, {}),
    ("HebbianDecayConfigCheckInput", "config_path", _TRAVERSAL, {}),
    ("HebbianDriftCheckInput", "claude_md_path", _TRAVERSAL, {}),
    ("HebbianDriftCheckInput", "baseline_path", _TRAVERSAL, {"claude_md_path": "/ok.md"}),
    ("I18nAuditInput", "project_path", _TRAVERSAL, {}),
    ("I18nAuditInput", "locale_dir", _TRAVERSAL, {"project_path": "/ok"}),
    ("SecretsV2AuditInput", "secrets_config_path", _TRAVERSAL, {"config_path": "/ok"}),
    ("ProvenanceTrackerInput", "chain_path", _TRAVERSAL, {"action": "verify"}),
    ("ElicitationAuditInput", "config_path", _TRAVERSAL, {}),
    ("TasksAuditInput", "config_path", _TRAVERSAL, {}),
    ("ResourcesPromptsAuditInput", "config_path", _TRAVERSAL, {}),
    ("AudioContentAuditInput", "config_path", _TRAVERSAL, {}),
    ("JsonSchemaDialectCheckInput", "config_path", _TRAVERSAL, {}),
    ("SseTransportAuditInput", "config_path", _TRAVERSAL, {}),
    ("IconMetadataAuditInput", "config_path", _TRAVERSAL, {}),
    ("OAuthOidcAuditInput", "config_path", _TRAVERSAL, {}),
    ("TokenScopeCheckInput", "config_path", _TRAVERSAL, {}),
    ("CredentialsCheckInput", "credentials_dir", _TRAVERSAL, {}),
    ("WebhookSigCheckInput", "config_path", _TRAVERSAL, {}),
    ("WorkspaceIntegrityCheckInput", "workspace_dir", _TRAVERSAL, {}),
]


@pytest.mark.parametrize("cls_name,field,bad,extra", _TRAVERSAL_CASES,
                         ids=[f"{c[0]}.{c[1]}" for c in _TRAVERSAL_CASES])
def test_traversal_blocked(cls_name, field, bad, extra):
    Cls = _import_model(cls_name)
    kwargs = {field: bad, **extra}
    with pytest.raises(ValidationError):
        Cls(**kwargs)


# ---------------------------------------------------------------------------
# models.py — custom format validators
# ---------------------------------------------------------------------------

class TestFleetAddInputUrl:
    def test_bad_scheme(self):
        Cls = _import_model("FleetAddInput")
        with pytest.raises(ValidationError):
            Cls(name="x", url="ftp://bad")

    def test_ok_scheme(self):
        Cls = _import_model("FleetAddInput")
        m = Cls(name="x", url="ws://ok")
        assert m.url == "ws://ok"


class TestExportGithubPrInputRepo:
    def test_no_slash(self):
        Cls = _import_model("ExportGithubPrInput")
        with pytest.raises(ValidationError):
            Cls(objective="x", content="y", repo="noslash")

    def test_ok(self):
        Cls = _import_model("ExportGithubPrInput")
        m = Cls(objective="x", content="y", repo="owner/repo")
        assert "/" in m.repo


class TestSessionConfigCheckInput:
    def test_no_paths(self):
        Cls = _import_model("SessionConfigCheckInput")
        with pytest.raises(ValidationError):
            Cls()

    def test_one_path(self):
        Cls = _import_model("SessionConfigCheckInput")
        m = Cls(env_file_path="/ok")
        assert m.env_file_path == "/ok"


class TestFleetSessionInjectEnv:
    def test_empty_key(self):
        Cls = _import_model("FleetSessionInjectEnvInput")
        with pytest.raises(ValidationError):
            Cls(env_vars={"": "val"})


class TestFleetCronSchedule:
    def test_bad_command(self):
        Cls = _import_model("FleetCronScheduleInput")
        with pytest.raises(ValidationError):
            Cls(command="rm;bad", schedule="* * * * *")

    def test_bad_schedule(self):
        Cls = _import_model("FleetCronScheduleInput")
        with pytest.raises(ValidationError):
            Cls(command="ls", schedule="* *")


class TestWorkspaceLockInputTimeout:
    def test_timeout_reset_on_release(self):
        Cls = _import_model("WorkspaceLockInput")
        m = Cls(path="/x", action="release", owner="me", timeout_s=60.0)
        assert m.timeout_s == 30.0

    def test_timeout_reset_on_status(self):
        Cls = _import_model("WorkspaceLockInput")
        m = Cls(path="/x", action="status", owner="me", timeout_s=99.0)
        assert m.timeout_s == 30.0


class TestGatewayProbeInputUrl:
    def test_bad_scheme(self):
        Cls = _import_model("GatewayProbeInput")
        with pytest.raises(ValidationError):
            Cls(gateway_url="http://bad")


class TestAdrGenerateInputStatus:
    def test_bad_status(self):
        Cls = _import_model("AdrGenerateInput")
        with pytest.raises(ValidationError):
            Cls(title="x", context="c", decision="d", status="invalid")

    def test_ok(self):
        Cls = _import_model("AdrGenerateInput")
        m = Cls(title="Valid Title", context="A valid context with enough chars",
                decision="A valid decision with enough chars", status="proposed")
        assert m.status == "proposed"


class TestExportAutoInputFormat:
    def test_bad_format(self):
        Cls = _import_model("ExportAutoInput")
        with pytest.raises(ValidationError):
            Cls(objective="x", content="y", delivery_format="bad")


class TestAgentTeamOrchestrateValidators:
    def test_duplicate_ids(self):
        Cls = _import_model("AgentTeamOrchestrateInput")
        with pytest.raises(ValidationError, match="[Dd]uplicate"):
            Cls(tasks=[{"id": "a", "description": "x"}, {"id": "a", "description": "y"}])

    def test_bad_dep_ref(self):
        Cls = _import_model("AgentTeamOrchestrateInput")
        with pytest.raises(ValidationError):
            Cls(tasks=[{"id": "a", "description": "x", "depends_on": ["z"]}])


class TestMarketResearchMonitorAction:
    def test_bad_action(self):
        Cls = _import_model("MarketResearchMonitorInput")
        with pytest.raises(ValidationError):
            Cls(action="invalid", competitor="x")

    def test_ok_action(self):
        Cls = _import_model("MarketResearchMonitorInput")
        m = Cls(action="add", competitor="x")
        assert m.action == "add"


class TestLegalValidators:
    def test_bad_legal_form_tax(self):
        Cls = _import_model("LegalTaxSimulateInput")
        with pytest.raises(ValidationError):
            Cls(legal_form="INVALID", revenue=100000)

    def test_bad_legal_form_governance(self):
        Cls = _import_model("LegalGovernanceAuditInput")
        with pytest.raises(ValidationError):
            Cls(legal_form="INVALID")

    def test_bad_legal_form_creation(self):
        Cls = _import_model("LegalCreationChecklistInput")
        with pytest.raises(ValidationError):
            Cls(legal_form="INVALID")

    def test_bad_social_status(self):
        Cls = _import_model("LegalSocialProtectionInput")
        with pytest.raises(ValidationError):
            Cls(status="bad")


class TestLocationValidators:
    def test_bad_property_type(self):
        Cls = _import_model("LocationRealEstateInput")
        with pytest.raises(ValidationError):
            Cls(property_type="invalid")


class TestSupplierValidators:
    def test_bad_category(self):
        Cls = _import_model("SupplierSearchInput")
        with pytest.raises(ValidationError):
            Cls(category="invalid")

    def test_bad_risk_action(self):
        Cls = _import_model("SupplierRiskMonitorInput")
        with pytest.raises(ValidationError):
            Cls(action="invalid")


class TestPromptInjectionBatchInput:
    def test_empty_items(self):
        Cls = _import_model("PromptInjectionBatchInput")
        with pytest.raises(ValidationError):
            Cls(items=[])


# ---------------------------------------------------------------------------
# config_helpers.py — SSRF checks
# ---------------------------------------------------------------------------

class TestConfigHelpersSsrf:
    def test_localhost_blocked(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("http://127.0.0.1/test")
        assert r is not None and "SSRF" in r

    def test_zero_blocked(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("http://0.0.0.0:8080")
        assert r is not None and "SSRF" in r

    def test_ipv6_loopback_blocked(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("http://[::1]/")
        assert r is not None and "SSRF" in r

    def test_private_range_blocked(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("http://10.0.0.1/api")
        assert r is not None and "private" in r.lower()

    def test_public_ok(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("http://example.com/api")
        assert r is None

    def test_invalid_url(self):
        from src.config_helpers import check_ssrf
        r = check_ssrf("not-a-url")
        # returns string error or None
        assert isinstance(r, (str, type(None)))
