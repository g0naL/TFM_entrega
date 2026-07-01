from __future__ import annotations

from pentest_orchestrator.hypotheses import hypothesis_from_proposal
from pentest_orchestrator.schemas import HypothesisProposal
from pentest_orchestrator.state import AgentState
from pentest_orchestrator.validation import task_from_hypothesis


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


def ftp_hypothesis() -> HypothesisProposal:
    return HypothesisProposal(
        service_port=21,
        service_name="ftp",
        observed_evidence="vsFTPd 2.3.4",
        weakness_class="known_vulnerable_version",
        hypothesis="FTP service may expose documented unsafe behavior.",
        validation_strategy="Perform controlled behavioral validation.",
        required_capability="ftp_behavior_validation",
        confidence="high",
        risk="high",
        rationale="The banner identifies a version worth validating in the lab.",
    )


def test_ftp_hypothesis_translates_to_governed_validation_task() -> None:
    state = base_state()
    state["tool_availability"] = {"vsftpd_backdoor_check": True}
    hypothesis = hypothesis_from_proposal(ftp_hypothesis())

    task = task_from_hypothesis(hypothesis, state)

    assert task is not None
    assert task["tool"] == "vsftpd_backdoor_check"
    assert task["args"] == [
        "192.168.114.128",
        "--ftp-port",
        "21",
        "--backdoor-port",
        "6200",
        "--timeout",
        "5",
    ]
    assert task["requires_human_approval"] is True
    assert task["source"] == f"hypothesis:{hypothesis['id']}"


def test_ftp_hypothesis_translates_to_proof_task_in_command_execution_mode() -> None:
    state = base_state()
    state["campaign_mode"] = "command_execution"
    state["tool_availability"] = {"vsftpd_backdoor_check": True}
    hypothesis = hypothesis_from_proposal(ftp_hypothesis())

    task = task_from_hypothesis(hypothesis, state)

    assert task is not None
    assert task["phase"] == "proof_of_impact"
    assert task["tool"] == "vsftpd_backdoor_check"
    assert "--proof-file" in task["args"]
    assert "/tmp/tfm_ftp_21_proof.txt" in task["args"]
    assert "--proof-text" in task["args"]
    assert "I was here ftp 21" in task["args"]
    assert task["requires_human_approval"] is True


def test_hypothesis_without_available_capability_returns_none() -> None:
    state = base_state()
    state["tool_availability"] = {"vsftpd_backdoor_check": False}
    hypothesis = hypothesis_from_proposal(ftp_hypothesis())

    assert task_from_hypothesis(hypothesis, state) is None


def test_version_correlation_prefers_metasploit_search_when_available() -> None:
    state = base_state()
    state["tool_availability"] = {"metasploit_search": True, "searchsploit": True}
    hypothesis = hypothesis_from_proposal(
        HypothesisProposal(
            service_port=3632,
            service_name="distccd",
            observed_evidence="distccd v1",
            weakness_class="known_vulnerable_version",
            hypothesis="distccd may have a public remote command execution module.",
            validation_strategy="Search public module candidates before any execution.",
            required_capability="service_version_correlation",
            confidence="high",
            risk="medium",
            rationale="The service/version is associated with public exploitation modules.",
        )
    )

    task = task_from_hypothesis(hypothesis, state)

    assert task is not None
    assert task["tool"] == "metasploit_search"
    assert task["requires_human_approval"] is False


def test_legacy_remote_access_hypothesis_translates_to_safe_banner_validation() -> None:
    state = base_state()
    state["tool_availability"] = {"nmap": True}
    hypothesis = hypothesis_from_proposal(
        HypothesisProposal(
            service_port=512,
            service_name="exec",
            observed_evidence="rexec netkit-rsh",
            weakness_class="insecure_service_exposure",
            hypothesis="Legacy r-service exposure should be validated.",
            validation_strategy="Validate the exposed banner without attempting login.",
            required_capability="legacy_remote_access_validation",
            confidence="high",
            risk="high",
            rationale="The service banner indicates a legacy remote-access service.",
        )
    )

    task = task_from_hypothesis(hypothesis, state)

    assert task is not None
    assert task["tool"] == "nmap"
    assert task["args"] == ["-sV", "-Pn", "-p", "512", "192.168.114.128"]
    assert task["requires_human_approval"] is False
    assert task["source"] == f"hypothesis:{hypothesis['id']}"


def test_remote_shell_file_write_hypothesis_translates_to_tcp_shell_proof() -> None:
    state = base_state()
    state["campaign_mode"] = "command_execution"
    state["tool_availability"] = {"tcp_shell_proof": True}
    hypothesis = hypothesis_from_proposal(
        HypothesisProposal(
            service_port=1524,
            service_name="bindshell",
            observed_evidence="Metasploitable root shell",
            weakness_class="misconfiguration",
            hypothesis="A shell-like channel may permit controlled proof-of-impact.",
            validation_strategy="Write a fixed proof file through the channel after approval.",
            required_capability="remote_shell_file_write_proof",
            confidence="high",
            risk="high",
            rationale="The service banner indicates a shell-like channel.",
        )
    )

    task = task_from_hypothesis(hypothesis, state)

    assert task is not None
    assert task["phase"] == "proof_of_impact"
    assert task["tool"] == "tcp_shell_proof"
    assert task["args"] == [
        "192.168.114.128",
        "--port",
        "1524",
        "--proof-file",
        "/tmp/tfm_bindshell_1524_proof.txt",
        "--proof-text",
        "I was here bindshell 1524",
        "--timeout",
        "5",
    ]
    assert task["requires_human_approval"] is True
