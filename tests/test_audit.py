from __future__ import annotations

from pentest_orchestrator.reporting import build_audit_appendix, build_execution_graph_mermaid, build_user_report
from pentest_orchestrator.state import AgentState, append_action_log, append_agent_activation


def base_state() -> AgentState:
    return {
        "scope": "lab",
        "target_host": "192.168.114.128",
        "target_ports": "1-1000",
        "n_tries": 0,
        "max_tries": 10,
        "prev_node": "orchestrator",
        "next_node": "recon",
        "history": [],
    }


def test_append_agent_activation_records_sequence_and_agent() -> None:
    state = base_state()

    first = append_agent_activation(state, "orchestrator")
    second = append_agent_activation(state, "recon")

    assert first["sequence"] == 1
    assert second["sequence"] == 2
    assert state["agent_activations"][1]["agent"] == "recon"


def test_build_audit_appendix_lists_executed_actions() -> None:
    state = base_state()
    state["tool_availability"] = {"nmap": True, "whatweb": False}
    append_agent_activation(state, "executor")
    append_action_log(
        state,
        stage="executed",
        tool="nmap",
        command="nmap -sV -Pn 192.168.114.128",
        risk="low",
        phase="recon",
        ok=True,
        reason="initial recon scan",
    )

    appendix = build_audit_appendix(state)

    assert "## Audit Appendix" in appendix
    assert "### Tool Availability" in appendix
    assert "whatweb: missing" in appendix
    assert "### Agent Activations" in appendix
    assert "executor" in appendix
    assert "### LangSmith Tracing" in appendix
    assert "### Execution Graph" in appendix
    assert "### Operator Playbook" in appendix
    assert "### Executed Actions" in appendix
    assert "nmap -sV -Pn 192.168.114.128" in appendix


def test_build_audit_appendix_lists_operator_playbook_candidates() -> None:
    state = base_state()
    state["operator_playbook_path"] = "operator_playbook.json"
    state["operator_playbook_considered"] = True
    state["operator_playbook"] = [
        {
            "id": "http-title",
            "when": "Use when HTTP is present.",
            "display_command": "nmap -Pn -p 80 --script http-title 192.168.114.128",
            "task": {
                "id": "task-http-title",
                "phase": "web_recon",
                "objective": "Get title",
                "tool": "nmap",
                "args": ["-Pn", "-p", "80", "--script", "http-title", "192.168.114.128"],
                "rationale": "Safe NSE title script.",
                "risk": "low",
                "requires_human_approval": False,
                "expected_signal": "Title",
                "status": "pending",
                "source": "operator_playbook:http-title",
            },
        }
    ]

    appendix = build_audit_appendix(state)

    assert "### Operator Playbook" in appendix
    assert "Considered by specialist: True" in appendix
    assert "http-title" in appendix
    assert "nmap -Pn -p 80 --script http-title 192.168.114.128" in appendix


def test_build_audit_appendix_lists_hypothesis_lifecycle() -> None:
    state = base_state()
    state["hypothesis_generation_attempted"] = True
    state["hypotheses"] = [
        {
            "id": "21-ftp-known-vulnerable-version-ftp-behavior-validation",
            "service_port": 21,
            "service_name": "ftp",
            "observed_evidence": "vsFTPd 2.3.4",
            "weakness_class": "known_vulnerable_version",
            "hypothesis": "FTP service may expose documented unsafe behavior.",
            "validation_strategy": "Perform controlled behavioral validation.",
            "required_capability": "ftp_behavior_validation",
            "confidence": "high",
            "risk": "high",
            "status": "validated",
            "rationale": "The banner identifies a version worth validating in the lab.",
        }
    ]

    appendix = build_audit_appendix(state)

    assert "### Hypothesis Lifecycle" in appendix
    assert "Generation attempted: True" in appendix
    assert "ftp_behavior_validation" in appendix
    assert "FTP service may expose documented unsafe behavior" in appendix


def test_build_execution_graph_mermaid_uses_agent_activation_order() -> None:
    state = base_state()
    append_agent_activation(state, "orchestrator")
    state["prev_node"] = "orchestrator"
    state["next_node"] = "recon"
    append_agent_activation(state, "recon")

    mermaid = build_execution_graph_mermaid(state)

    assert "flowchart TD" in mermaid
    assert "001 orchestrator" in mermaid
    assert "002 recon" in mermaid
    assert "N1 --> N2" in mermaid


def test_build_audit_appendix_groups_actions_by_try() -> None:
    state = base_state()
    state["current_try"] = 1
    append_action_log(
        state,
        stage="proposed",
        tool="whatweb",
        command="whatweb http://192.168.114.128",
        risk="low",
        task_id="task-web",
        phase="web_recon",
        ok=None,
        reason="fingerprint web",
    )
    state["current_try"] = 2
    append_action_log(
        state,
        stage="execution_failed",
        tool="nuclei",
        command="nuclei -u http://192.168.114.128",
        risk="medium",
        task_id="task-nuclei",
        phase="vulnerability_scanning",
        ok=False,
        reason="executor result",
    )

    appendix = build_audit_appendix(state)

    assert "### Actions By Try" in appendix
    assert "#### Try 1" in appendix
    assert "#### Try 2" in appendix
    assert "whatweb http://192.168.114.128" in appendix
    assert "nuclei -u http://192.168.114.128" in appendix


def test_build_audit_appendix_lists_complete_findings_catalog() -> None:
    state = base_state()
    state["findings"] = [
        {
            "id": "finding-001",
            "task_id": "task-1",
            "title": "Anonymous FTP allowed",
            "severity": "medium",
            "confidence": "high",
            "evidence": "ftp-anon reported writable anonymous access",
            "recommendation": "Disable anonymous FTP or restrict it to read-only.",
        },
        {
            "id": "finding-002",
            "task_id": "task-2",
            "title": "Outdated Apache version",
            "severity": "low",
            "confidence": "medium",
            "evidence": "Apache httpd 2.2.8 banner observed",
            "recommendation": "Upgrade Apache and verify exposed modules.",
        },
    ]

    appendix = build_audit_appendix(state)

    assert "### Findings Catalog" in appendix
    assert "finding-001 - Anonymous FTP allowed" in appendix
    assert "finding-002 - Outdated Apache version" in appendix
    assert "Disable anonymous FTP" in appendix
    assert "Upgrade Apache" in appendix


def test_build_audit_appendix_lists_evidence_catalog() -> None:
    state = base_state()
    state["evidence"] = [
        {
            "id": "ev-1",
            "task_id": "task-1",
            "command": "whatweb http://192.168.114.128",
            "ok": True,
            "summary": "Apache, PHP",
            "output_head": "Apache[2.2.8], PHP[5.2.4]",
        },
        {
            "id": "ev-2",
            "task_id": "task-2",
            "command": "nuclei -u http://192.168.114.128",
            "ok": False,
            "summary": "template path missing",
            "output_head": "no templates provided for scan",
        },
    ]

    appendix = build_audit_appendix(state)

    assert "### Evidence Catalog" in appendix
    assert "ev-1 - OK" in appendix
    assert "ev-2 - FAILED" in appendix
    assert "Apache[2.2.8]" in appendix
    assert "no templates provided" in appendix


def test_build_user_report_keeps_audit_noise_out_of_user_report() -> None:
    state = base_state()
    state["recon_ports_scanned"] = "1-1000,1524,3306,6667,8180"
    state["services"] = [
        {
            "port": 21,
            "proto": "tcp",
            "state": "open",
            "service": "ftp",
            "version_line": "vsftpd 2.3.4",
        }
    ]
    state["findings"] = [
        {
            "id": "finding-001",
            "task_id": "task-vsftpd",
            "title": "vsFTPd backdoor behavior confirmed",
            "severity": "critical",
            "confidence": "high",
            "validation_status": "validated_controlled",
            "evidence": "Backdoor port status: open. Verdict confirmed in the authorized lab.",
            "recommendation": "Remove the vulnerable vsFTPd build.",
        }
    ]
    append_action_log(
        state,
        stage="executed",
        tool="nmap",
        command="nmap -sV -Pn -p 21 192.168.114.128",
        risk="low",
        phase="recon",
        ok=True,
        reason="initial recon scan",
    )

    report = build_user_report(state)

    assert "# Pentest Lab Report" in report
    assert "Validation status: validated_controlled" in report
    assert "Ports scanned: 1-1000,1524,3306,6667,8180" in report
    assert "## Audit Appendix" not in report
    assert "### Executed Actions" not in report
    assert "nmap -sV -Pn -p 21" not in report


def test_build_user_report_deduplicates_related_findings_by_strongest_evidence() -> None:
    state = base_state()
    state["findings"] = [
        {
            "id": "finding-001",
            "task_id": "task-vsftpd-proof",
            "title": "vsFTPd backdoor proof-of-impact confirmed on port 21",
            "severity": "critical",
            "confidence": "high",
            "validation_status": "proof_of_impact_observed",
            "evidence": "Backdoor port status: OPEN. Proof file write: CONFIRMED.",
            "recommendation": "Remove the vulnerable vsFTPd build.",
        },
        {
            "id": "finding-002",
            "task_id": "task-vsftpd-validation",
            "title": "vsFTPd backdoor behavior confirmed",
            "severity": "critical",
            "confidence": "high",
            "validation_status": "validated_controlled",
            "evidence": "Backdoor port status: OPEN.",
            "recommendation": "Remove the vulnerable vsFTPd build.",
        },
        {
            "id": "finding-003",
            "task_id": "task-ftp-anon-1",
            "title": "Anonymous FTP access appears enabled",
            "severity": "medium",
            "confidence": "high",
            "validation_status": "observed_exposure",
            "evidence": "ftp-anon: Anonymous FTP login allowed.",
            "recommendation": "Disable anonymous FTP.",
        },
        {
            "id": "finding-004",
            "task_id": "task-ftp-anon-2",
            "title": "Anonymous FTP access appears enabled",
            "severity": "medium",
            "confidence": "high",
            "validation_status": "observed_exposure",
            "evidence": "ftp-anon: Anonymous FTP login allowed.",
            "recommendation": "Disable anonymous FTP.",
        },
    ]

    report = build_user_report(state)

    assert "2 unique report findings (4 raw evidence findings in audit)" in report
    assert "vsFTPd backdoor proof-of-impact confirmed on port 21" in report
    assert "vsFTPd backdoor behavior confirmed" not in report
    assert report.count("Anonymous FTP access appears enabled") == 1
