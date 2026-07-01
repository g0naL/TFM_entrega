from __future__ import annotations

import pytest

from pentest_orchestrator.graph import OpenAIResponsesLLM


def test_openai_provider_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        OpenAIResponsesLLM(model="gpt-5.5", temperature=0.0, timeout_s=120.0, max_retries=2)
