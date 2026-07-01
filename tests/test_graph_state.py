from __future__ import annotations

from pentest_orchestrator.config import LabSettings
from pentest_orchestrator.graph import build_initial_state


def test_build_initial_state_includes_audit_fields() -> None:
    state = build_initial_state(LabSettings())

    assert state["agent_activations"] == []
    assert state["action_log"] == []
    assert state["task_queue"] == []
    assert state["operator_playbook_path"] == "operator_playbook.json"
    assert state["operator_playbook"] == []
    assert state["operator_playbook_errors"] == []
    assert state["operator_playbook_considered"] is False
    assert state["hypotheses"] == []
    assert state["hypothesis_generation_attempted"] is False
    assert state["current_hypothesis_id"] is None
    assert state["campaign_mode"] == "detection"
    assert state["known_vulnerabilities"] == []
    assert state["known_vulnerabilities_source"] == ""
    assert state["round_task_ids"] == []
    assert state["current_try"] == 0
    assert state["stop_reason"] is None
    assert state["last_failure"] is None
    assert state["needs_specialist_replan"] is False
    assert state["max_actions_per_try"] > 0
    assert state["max_runtime_s"] > 0
    assert state["human_wait_total_s"] == 0.0
    assert state["command_timeout_s"] > 0
    assert "nmap" in state["tool_availability"]
    assert state["tool_availability"]["http_probe"] is True
