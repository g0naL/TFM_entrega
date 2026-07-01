from __future__ import annotations

from collections import Counter

from pentest_orchestrator.tools import TOOL_REGISTRY, get_tool_spec


def test_registry_has_three_tools_for_core_domains() -> None:
    domains = Counter(spec.domain for spec in TOOL_REGISTRY.values())

    assert domains["active_directory_linux"] >= 3
    assert domains["web_recon"] >= 3
    assert domains["web_content_discovery"] >= 3
    assert domains["bruteforce"] >= 3


def test_bruteforce_tools_require_approval() -> None:
    for name in ["hydra", "medusa", "ncrack"]:
        spec = get_tool_spec(name)

        assert spec is not None
        assert spec.risk == "high"
        assert spec.requires_approval is True
