from __future__ import annotations

import json

from pentest_orchestrator.playbook import load_operator_playbook
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
        "tool_availability": {"nmap": True, "http_probe": True, "ffuf": True},
        "services": [
            {
                "port": 80,
                "proto": "tcp",
                "state": "open",
                "service": "http",
                "version_line": "Apache httpd 2.2.8",
            }
        ],
    }


def write_playbook(tmp_path, data: dict) -> str:
    path = tmp_path / "operator_playbook.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_load_operator_playbook_resolves_command_template(tmp_path) -> None:
    path = write_playbook(
        tmp_path,
        {
            "candidates": [
                {
                    "id": "http-title",
                    "enabled": True,
                    "phase": "web_recon",
                    "objective": "Get title",
                    "command": "nmap -Pn -p {first_http_port} --script http-title {target_host}",
                    "requires_service": "http",
                    "rationale": "Safe NSE title script.",
                    "risk": "low",
                    "requires_human_approval": False,
                    "expected_signal": "Title",
                }
            ]
        },
    )

    result = load_operator_playbook(path, base_state())

    assert result.errors == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate["display_command"] == "nmap -Pn -p 80 --script http-title 192.168.114.128"
    assert candidate["task"]["tool"] == "nmap"
    assert candidate["task"]["args"] == ["-Pn", "-p", "80", "--script", "http-title", "192.168.114.128"]
    assert candidate["task"]["source"] == "operator_playbook:http-title"


def test_load_operator_playbook_accepts_simple_commands_list(tmp_path) -> None:
    path = write_playbook(
        tmp_path,
        {
            "commands": [
                "nmap -Pn -p {first_http_port} --script http-title {target_host}",
            ]
        },
    )

    result = load_operator_playbook(path, base_state())

    assert result.errors == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate["id"] == "operator-command-1"
    assert candidate["display_command"] == "nmap -Pn -p 80 --script http-title 192.168.114.128"
    assert candidate["task"]["phase"] == "recon"
    assert candidate["task"]["risk"] == "low"
    assert candidate["task"]["requires_human_approval"] is False
    assert candidate["task"]["source"] == "operator_playbook:operator-command-1"


def test_load_operator_playbook_accepts_vsftpd_conditional_candidate(tmp_path) -> None:
    path = write_playbook(
        tmp_path,
        {
            "candidates": [
                {
                    "id": "vsftpd-234-backdoor-check",
                    "enabled": True,
                    "phase": "vulnerability_scanning",
                    "objective": "Check vsFTPd backdoor",
                    "command": "vsftpd_backdoor_check {target_host} --ftp-port 21 --backdoor-port 6200 --timeout 5",
                    "requires_port": 21,
                    "requires_service": "ftp",
                    "rationale": "Controlled lab verification.",
                    "risk": "high",
                    "requires_human_approval": True,
                    "expected_signal": "Port 6200 opens after trigger.",
                }
            ]
        },
    )
    state = base_state()
    state["tool_availability"]["vsftpd_backdoor_check"] = True
    state["services"] = [
        {
            "port": 21,
            "proto": "tcp",
            "state": "open",
            "service": "ftp",
            "version_line": "vsFTPd 2.3.4",
        }
    ]

    result = load_operator_playbook(path, state)

    assert result.errors == []
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate["display_command"] == "vsftpd_backdoor_check 192.168.114.128 --ftp-port 21 --backdoor-port 6200 --timeout 5"
    assert candidate["task"]["tool"] == "vsftpd_backdoor_check"
    assert candidate["task"]["phase"] == "vulnerability_scanning"
    assert candidate["task"]["requires_human_approval"] is True


def test_load_operator_playbook_skips_disabled_and_non_matching_service(tmp_path) -> None:
    path = write_playbook(
        tmp_path,
        {
            "candidates": [
                {
                    "id": "disabled",
                    "enabled": False,
                    "phase": "web_recon",
                    "objective": "Disabled",
                    "tool": "http_probe",
                    "args": ["{http_url}"],
                    "rationale": "Disabled",
                    "risk": "low",
                    "requires_human_approval": False,
                    "expected_signal": "Headers",
                },
                {
                    "id": "ftp-only",
                    "enabled": True,
                    "phase": "service_enum",
                    "objective": "FTP check",
                    "tool": "nmap",
                    "args": ["-Pn", "-p", "21", "--script", "ftp-anon", "{target_host}"],
                    "requires_service": "ftp",
                    "rationale": "FTP only",
                    "risk": "low",
                    "requires_human_approval": False,
                    "expected_signal": "Anonymous FTP",
                },
            ]
        },
    )

    result = load_operator_playbook(path, base_state())

    assert result.candidates == []
    assert result.errors == []


def test_load_operator_playbook_reports_invalid_candidate(tmp_path) -> None:
    path = write_playbook(
        tmp_path,
        {
            "candidates": [
                {
                    "id": "unknown-tool",
                    "enabled": True,
                    "phase": "recon",
                    "objective": "Unknown",
                    "command": "not-a-tool {target_host}",
                    "rationale": "Should fail",
                    "risk": "low",
                    "requires_human_approval": False,
                    "expected_signal": "None",
                }
            ]
        },
    )

    result = load_operator_playbook(path, base_state())

    assert result.candidates == []
    assert "unknown-tool" in result.errors[0]
