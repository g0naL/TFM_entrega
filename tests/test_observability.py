from __future__ import annotations

from pentest_orchestrator.config import LangSmithSettings
from pentest_orchestrator.observability import langsmith_runnable_config, langsmith_trace_context


def test_langsmith_settings_reads_project_env(monkeypatch) -> None:
    monkeypatch.setenv("PENTEST_LANGSMITH_ENABLED", "true")
    monkeypatch.setenv("PENTEST_LANGSMITH_PROJECT", "tfm-test-project")
    monkeypatch.setenv("PENTEST_LANGSMITH_HIDE_INPUTS", "true")

    settings = LangSmithSettings.from_env()

    assert settings.enabled is True
    assert settings.project == "tfm-test-project"
    assert settings.hide_inputs is True


def test_langsmith_context_disables_when_api_key_missing(monkeypatch) -> None:
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    settings = LangSmithSettings(enabled=True, project="tfm-test-project")

    with langsmith_trace_context(
        settings,
        run_id="run-1",
        target_host="192.168.114.128",
        target_ports="1-1000",
        approval_mode="auto-low",
    ) as status:
        assert status["active"] is False
        assert status["reason"] == "missing_LANGSMITH_API_KEY"
        assert status["project"] == "tfm-test-project"


def test_langsmith_runnable_config_includes_run_metadata() -> None:
    settings = LangSmithSettings(project="tfm-test-project")

    config = langsmith_runnable_config(
        settings,
        run_id="run-1",
        target_host="192.168.114.128",
        target_ports="1-1000",
        approval_mode="auto-low",
    )

    assert config["run_name"] == "pentest-campaign-run-1"
    assert "multiagent-pentest" in config["tags"]
    assert config["metadata"]["tfm_run_id"] == "run-1"
    assert config["metadata"]["langsmith_project"] == "tfm-test-project"
