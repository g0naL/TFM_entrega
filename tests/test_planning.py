from __future__ import annotations

from pentest_orchestrator.planning import merge_replanned_task_queues, next_round_task, seed_tasks_from_services, select_round_tasks
from pentest_orchestrator.state import AgentState, TaskItem


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


def test_seed_tasks_from_services_creates_web_followups() -> None:
    state = base_state()
    state["tool_availability"] = {
        "metasploit_search": True,
        "searchsploit": True,
        "whatweb": True,
        "nuclei": True,
        "http_probe": True,
    }
    state["services"] = [
        {
            "port": 80,
            "proto": "tcp",
            "state": "open",
            "service": "http",
            "version_line": "Apache httpd 2.2.8",
        }
    ]

    tasks = seed_tasks_from_services(state)
    tools = {task["tool"] for task in tasks}

    assert "searchsploit" in tools
    assert "metasploit_search" in tools
    assert "http_probe" in tools
    assert "whatweb" in tools
    assert "nuclei" in tools
    assert any(task["requires_human_approval"] for task in tasks if task["tool"] == "nuclei")


def test_seed_tasks_from_services_skips_missing_external_tools() -> None:
    state = base_state()
    state["tool_availability"] = {
        "metasploit_search": False,
        "searchsploit": False,
        "whatweb": False,
        "nuclei": False,
        "http_probe": True,
    }
    state["services"] = [
        {
            "port": 80,
            "proto": "tcp",
            "state": "open",
            "service": "http",
            "version_line": "Apache httpd 2.2.8",
        }
    ]

    tasks = seed_tasks_from_services(state)
    tools = {task["tool"] for task in tasks}

    assert "http_probe" in tools
    assert "metasploit_search" not in tools
    assert "searchsploit" not in tools
    assert "whatweb" not in tools
    assert "nuclei" not in tools


def test_seed_tasks_from_services_creates_ftp_safe_script() -> None:
    state = base_state()
    state["tool_availability"] = {"nmap": True}
    state["services"] = [
        {
            "port": 21,
            "proto": "tcp",
            "state": "open",
            "service": "ftp",
            "version_line": "vsftpd 2.3.4",
        }
    ]

    tasks = seed_tasks_from_services(state)

    assert any(task["tool"] == "nmap" and "ftp-anon" in task["args"] for task in tasks)


def test_merge_replanned_task_queues_prioritizes_fresh_non_duplicates() -> None:
    failed_existing: TaskItem = {
        "id": "failed",
        "phase": "web_recon",
        "objective": "failed fingerprint",
        "tool": "whatweb",
        "args": ["http://192.168.114.128"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
        "expected_signal": "tech",
        "status": "failed",
        "source": "test",
    }
    pending_existing: TaskItem = {
        "id": "pending",
        "phase": "web_recon",
        "objective": "old pending",
        "tool": "http_probe",
        "args": ["http://192.168.114.128"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
        "expected_signal": "headers",
        "status": "pending",
        "source": "test",
    }
    fresh_task: TaskItem = {
        "id": "fresh",
        "phase": "web_recon",
        "objective": "corrected alternative",
        "tool": "ffuf",
        "args": ["-u", "http://192.168.114.128/FUZZ"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
        "expected_signal": "paths",
        "status": "pending",
        "source": "test",
    }
    duplicate_failed = dict(failed_existing)
    duplicate_failed["id"] = "duplicate"
    duplicate_failed["status"] = "pending"

    merged = merge_replanned_task_queues([failed_existing, pending_existing], [duplicate_failed, fresh_task])  # type: ignore[list-item]

    assert [task["id"] for task in merged] == ["fresh", "failed", "pending"]
    assert merged[1]["status"] == "failed"


def test_select_round_tasks_prioritizes_proof_of_impact() -> None:
    low_task: TaskItem = {
        "id": "low",
        "phase": "service_enum",
        "objective": "banner",
        "tool": "nmap",
        "args": ["-sV", "-Pn", "-p", "23", "192.168.114.128"],
        "rationale": "check",
        "risk": "low",
        "requires_human_approval": False,
        "expected_signal": "banner",
        "status": "pending",
        "source": "test",
    }
    proof_task: TaskItem = {
        "id": "proof",
        "phase": "proof_of_impact",
        "objective": "proof",
        "tool": "tcp_shell_proof",
        "args": [
            "192.168.114.128",
            "--port",
            "1524",
            "--proof-file",
            "/tmp/tfm_bindshell_1524_proof.txt",
            "--proof-text",
            "I was here bindshell 1524",
        ],
        "rationale": "proof",
        "risk": "high",
        "requires_human_approval": True,
        "expected_signal": "file",
        "status": "pending",
        "source": "test",
    }

    selected = select_round_tasks([low_task, proof_task], 2)

    assert [task["id"] for task in selected] == ["proof", "low"]
    assert next_round_task([low_task, proof_task], ["low", "proof"])["id"] == "proof"
