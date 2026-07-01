from __future__ import annotations

from pentest_orchestrator.policy import validate_policy
from pentest_orchestrator.schemas import CommandProposal
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


def test_policy_allows_in_scope_web_recon() -> None:
    proposal = CommandProposal(
        phase="web_recon",
        tool="whatweb",
        args=["http://192.168.114.128"],
        rationale="fingerprint",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, base_state(), "192.168.114.0/24")

    assert decision.allowed is True
    assert decision.requires_human_approval is False


def test_policy_blocks_out_of_scope_url() -> None:
    proposal = CommandProposal(
        phase="web_recon",
        tool="whatweb",
        args=["http://8.8.8.8"],
        rationale="fingerprint",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, base_state(), "192.168.114.0/24")

    assert decision.allowed is False
    assert "outside authorized networks" in decision.reason


def test_policy_blocks_unapproved_nmap_script() -> None:
    proposal = CommandProposal(
        phase="service_enum",
        tool="nmap",
        args=["-Pn", "-p", "21", "--script", "ftp-brute", "192.168.114.128"],
        rationale="unsafe script",
        risk="medium",
        requires_human_approval=True,
    )

    decision = validate_policy(proposal, base_state(), "192.168.114.0/24")

    assert decision.allowed is False
    assert "Nmap script outside" in decision.reason


def test_policy_requires_nuclei_rate_limit() -> None:
    proposal = CommandProposal(
        phase="vulnerability_scanning",
        tool="nuclei",
        args=["-u", "http://192.168.114.128", "-severity", "low,medium"],
        rationale="scan",
        risk="medium",
        requires_human_approval=True,
    )

    decision = validate_policy(proposal, base_state(), "192.168.114.0/24")

    assert decision.allowed is False
    assert "-rate-limit" in decision.reason


def test_policy_blocks_operator_playbook_outside_command_execution_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "detection"
    state["task_queue"] = [
        {
            "id": "operator-task",
            "phase": "web_recon",
            "objective": "operator command",
            "tool": "http_probe",
            "args": ["http://192.168.114.128"],
            "rationale": "operator",
            "risk": "low",
            "requires_human_approval": False,
            "expected_signal": "headers",
            "status": "proposed",
            "source": "operator_playbook:operator-command-1",
        }
    ]
    proposal = CommandProposal(
        task_id="operator-task",
        phase="web_recon",
        tool="http_probe",
        args=["http://192.168.114.128"],
        rationale="operator command",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is False
    assert "command_execution" in decision.reason


def test_policy_blocks_operator_playbook_without_prior_findings() -> None:
    state = base_state()
    state["campaign_mode"] = "command_execution"
    state["findings"] = []
    state["task_queue"] = [
        {
            "id": "operator-task",
            "phase": "web_recon",
            "objective": "operator command",
            "tool": "http_probe",
            "args": ["http://192.168.114.128"],
            "rationale": "operator",
            "risk": "low",
            "requires_human_approval": False,
            "expected_signal": "headers",
            "status": "proposed",
            "source": "operator_playbook:operator-command-1",
        }
    ]
    proposal = CommandProposal(
        task_id="operator-task",
        phase="web_recon",
        tool="http_probe",
        args=["http://192.168.114.128"],
        rationale="operator command",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is False
    assert "prior findings" in decision.reason


def test_policy_allows_targeted_offline_audit_in_verification_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "verification"
    state["known_vulnerabilities"] = ["Known leaked hash requires type confirmation"]
    proposal = CommandProposal(
        phase="offline_audit",
        tool="hashid",
        args=["5f4dcc3b5aa765d61d8327deb882cf99"],
        rationale="confirm hash type for known vulnerability",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is True


def test_policy_blocks_offline_audit_in_detection_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "detection"
    proposal = CommandProposal(
        phase="offline_audit",
        tool="hashid",
        args=["5f4dcc3b5aa765d61d8327deb882cf99"],
        rationale="broad offline audit",
        risk="low",
        requires_human_approval=False,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is False
    assert "detection" in decision.reason


def test_policy_blocks_proof_of_impact_outside_command_execution_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "detection"
    proposal = CommandProposal(
        phase="proof_of_impact",
        tool="tcp_shell_proof",
        args=[
            "192.168.114.128",
            "--port",
            "1524",
            "--proof-file",
            "/tmp/tfm_bindshell_1524_proof.txt",
            "--proof-text",
            "I was here bindshell 1524",
        ],
        rationale="controlled proof",
        risk="high",
        requires_human_approval=True,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is False
    assert "command_execution" in decision.reason


def test_policy_allows_governed_proof_of_impact_in_command_execution_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "command_execution"
    proposal = CommandProposal(
        phase="proof_of_impact",
        tool="tcp_shell_proof",
        args=[
            "192.168.114.128",
            "--port",
            "1524",
            "--proof-file",
            "/tmp/tfm_bindshell_1524_proof.txt",
            "--proof-text",
            "I was here bindshell 1524",
        ],
        rationale="controlled proof",
        risk="high",
        requires_human_approval=True,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is True
    assert decision.requires_human_approval is True


def test_policy_allows_metasploit_proof_with_human_approval_in_command_execution_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "command_execution"
    proposal = CommandProposal(
        phase="proof_of_impact",
        tool="metasploit_proof",
        args=[
            "192.168.114.128",
            "--module",
            "exploit/unix/misc/distcc_exec",
            "--rport",
            "3632",
            "--payload",
            "cmd/unix/generic",
            "--proof-file",
            "/tmp/tfm_distccd_3632_proof.txt",
            "--proof-text",
            "I was here distccd 3632",
        ],
        rationale="controlled metasploit proof",
        risk="high",
        requires_human_approval=True,
    )

    decision = validate_policy(proposal, state, "192.168.114.0/24")

    assert decision.allowed is True
    assert decision.requires_human_approval is True
