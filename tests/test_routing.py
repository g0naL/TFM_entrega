from __future__ import annotations

from pentest_orchestrator.routing import decide_next_node
from pentest_orchestrator.state import AgentState


def base_state() -> AgentState:
    return {
        "scope": "lab",
        "target_host": "192.168.114.128",
        "target_ports": "1-1000",
        "n_tries": 0,
        "max_tries": 10,
        "prev_node": "",
        "next_node": "recon",
        "history": [],
    }


def test_decide_next_node_starts_with_recon() -> None:
    assert decide_next_node(base_state()) == "recon"


def test_decide_next_node_routes_to_human_approval_when_required() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["proposal"] = {
        "action_type": "RUN_COMMAND",
        "tool": "nmap",
        "args": ["-sV", "192.168.114.128"],
        "rationale": "check",
        "risk": "medium",
        "requires_human_approval": True,
    }
    state["human_check"] = None
    state["policy_check"] = {"allowed": True, "reason": "ok", "requires_human_approval": True}

    assert decide_next_node(state) == "human_approval"


def test_decide_next_node_routes_to_policy_before_approval() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["proposal"] = {
        "action_type": "RUN_COMMAND",
        "tool": "nmap",
        "args": ["-sV", "192.168.114.128"],
        "rationale": "check",
        "risk": "medium",
        "requires_human_approval": True,
    }
    state["human_check"] = None

    assert decide_next_node(state) == "policy"


def test_decide_next_node_routes_to_specialist_when_pending_tasks_exist() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["task_queue"] = [
        {
            "id": "task-1",
            "phase": "web_recon",
            "objective": "fingerprint",
            "tool": "whatweb",
            "args": ["http://192.168.114.128"],
            "rationale": "check",
            "risk": "low",
            "requires_human_approval": False,
            "expected_signal": "tech",
            "status": "pending",
            "source": "test",
        }
    ]

    assert decide_next_node(state) == "specialist"


def test_decide_next_node_stops_at_max_tries() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["n_tries"] = 10

    assert decide_next_node(state) == "reporter"


def test_decide_next_node_continues_current_round_at_max_tries() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["n_tries"] = 10
    state["round_task_ids"] = ["task-1"]
    state["task_queue"] = [
        {
            "id": "task-1",
            "phase": "web_recon",
            "objective": "fingerprint",
            "tool": "whatweb",
            "args": ["http://192.168.114.128"],
            "rationale": "check",
            "risk": "low",
            "requires_human_approval": False,
            "expected_signal": "tech",
            "status": "pending",
            "source": "test",
        }
    ]

    assert decide_next_node(state) == "specialist"


def test_decide_next_node_returns_to_specialist_after_command_failure() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["proposal"] = {
        "action_type": "RUN_COMMAND",
        "tool": "whatweb",
        "args": ["http://192.168.114.128"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
    }
    state["policy_check"] = {"allowed": True, "reason": "ok", "requires_human_approval": False}
    state["execution_result"] = "binary failed"
    state["execution_ok"] = False

    assert decide_next_node(state) == "specialist"


def test_decide_next_node_reports_command_failure_when_max_tries_reached() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["n_tries"] = 10
    state["proposal"] = {
        "action_type": "RUN_COMMAND",
        "tool": "whatweb",
        "args": ["http://192.168.114.128"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
    }
    state["policy_check"] = {"allowed": True, "reason": "ok", "requires_human_approval": False}
    state["execution_result"] = "binary failed"
    state["execution_ok"] = False

    assert decide_next_node(state) == "reporter"


def test_decide_next_node_routes_to_hypothesis_generator_after_plan() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"

    assert decide_next_node(state) == "hypothesis_generator"


def test_decide_next_node_routes_suspected_hypothesis_to_validation_planner() -> None:
    state = base_state()
    state["recon_raw"] = "scan"
    state["plan"] = "plan"
    state["hypothesis_generation_attempted"] = True
    state["hypotheses"] = [
        {
            "id": "h1",
            "service_port": 21,
            "service_name": "ftp",
            "observed_evidence": "vsFTPd 2.3.4",
            "weakness_class": "known_vulnerable_version",
            "hypothesis": "FTP behavior should be validated.",
            "validation_strategy": "controlled behavior validation",
            "required_capability": "ftp_behavior_validation",
            "confidence": "high",
            "risk": "high",
            "status": "suspected",
            "rationale": "banner evidence",
        }
    ]

    assert decide_next_node(state) == "validation_planner"
