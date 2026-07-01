from __future__ import annotations

import pytest

from pentest_orchestrator.config import DEFAULT_LAB_EXTRA_PORTS, LabSettings, LlmSettings


def test_lab_settings_default_expands_common_vulnerable_lab_ports() -> None:
    settings = LabSettings()

    assert settings.expand_lab_ports is True
    assert "1524" in settings.lab_extra_ports
    assert "8180" in settings.lab_extra_ports
    assert settings.lab_extra_ports == DEFAULT_LAB_EXTRA_PORTS


def test_llm_settings_accepts_openai_provider_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTEST_LLM_PROVIDER", "openai")
    monkeypatch.setenv("PENTEST_LLM_MODEL", "gpt-5.5")
    monkeypatch.setenv("PENTEST_OPENAI_TIMEOUT_S", "180")
    monkeypatch.setenv("PENTEST_OPENAI_MAX_RETRIES", "4")

    settings = LlmSettings.from_env()

    assert settings.provider == "openai"
    assert settings.planner_model == "gpt-5.5"
    assert settings.specialist_model == "gpt-5.5"
    assert settings.openai_timeout_s == 180.0
    assert settings.openai_max_retries == 4


def test_llm_settings_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTEST_LLM_PROVIDER", "bad-provider")

    with pytest.raises(ValueError):
        LlmSettings.from_env()
