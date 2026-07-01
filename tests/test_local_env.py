from __future__ import annotations

from pentest_orchestrator.local_env import load_local_env


def test_load_local_env_reads_export_style_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGSMITH_ENDPOINT", raising=False)
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "\n".join(
            [
                "export LANGSMITH_TRACING=true",
                "export LANGSMITH_ENDPOINT=https://eu.api.smith.langchain.com",
                'export LANGSMITH_PROJECT="a"',
            ]
        ),
        encoding="utf-8",
    )

    loaded = load_local_env(env_file)

    assert loaded["LANGSMITH_TRACING"] == "true"
    assert loaded["LANGSMITH_ENDPOINT"] == "https://eu.api.smith.langchain.com"
    assert loaded["LANGSMITH_PROJECT"] == "a"


def test_load_local_env_handles_utf8_bom(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    env_file = tmp_path / ".env.local"
    env_file.write_text("\ufeffLANGSMITH_TRACING=true", encoding="utf-8")

    loaded = load_local_env(env_file)

    assert loaded["LANGSMITH_TRACING"] == "true"


def test_load_local_env_does_not_override_existing_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LANGSMITH_PROJECT", "existing")
    env_file = tmp_path / ".env.local"
    env_file.write_text('LANGSMITH_PROJECT="from-file"', encoding="utf-8")

    loaded = load_local_env(env_file)

    assert "LANGSMITH_PROJECT" not in loaded
    assert loaded == {}
