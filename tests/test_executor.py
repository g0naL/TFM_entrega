from __future__ import annotations

from pentest_orchestrator.executor import (
    run_metasploit_proof,
    run_tcp_shell_proof,
    run_vsftpd_backdoor_check,
    validate_tool_invocation,
)


def test_validate_tool_invocation_accepts_allowlisted_nmap() -> None:
    ok, reason, parts = validate_tool_invocation("nmap", ["-sV", "-Pn", "-p", "1-1000", "192.168.114.128"])

    assert ok is True
    assert reason == ""
    assert parts[0].lower().endswith("nmap") or parts[0].lower().endswith("nmap.exe")


def test_validate_tool_invocation_blocks_disallowed_flag() -> None:
    ok, reason, _ = validate_tool_invocation("nmap", ["--interactive", "192.168.114.128"])

    assert ok is False
    assert "Flag not allowed" in reason


def test_validate_tool_invocation_blocks_shell_control_tokens() -> None:
    ok, reason, _ = validate_tool_invocation("nmap", ["-sV", "127.0.0.1", "&&", "whoami"])

    assert ok is False
    assert "Blocked shell control token" in reason


def test_validate_tool_invocation_accepts_ad_linux_tool() -> None:
    ok, reason, parts = validate_tool_invocation("netexec", ["smb", "192.168.114.128", "--shares"])

    assert ok is True
    assert reason == ""
    assert parts[:2] == ["netexec", "smb"]


def test_validate_tool_invocation_accepts_web_discovery_tool() -> None:
    ok, reason, parts = validate_tool_invocation("ffuf", ["-u", "http://192.168.114.128/FUZZ", "-w", "wordlist.txt"])

    assert ok is True
    assert reason == ""
    assert parts[0].lower().endswith("ffuf") or parts[0].lower().endswith("ffuf.exe")


def test_validate_tool_invocation_accepts_builtin_http_probe() -> None:
    ok, reason, parts = validate_tool_invocation("http_probe", ["http://192.168.114.128"])

    assert ok is True
    assert reason == ""
    assert parts == ["http_probe", "http://192.168.114.128"]


def test_validate_tool_invocation_accepts_builtin_vsftpd_check() -> None:
    ok, reason, parts = validate_tool_invocation(
        "vsftpd_backdoor_check",
        ["192.168.114.128", "--ftp-port", "21", "--backdoor-port", "6200", "--timeout", "5"],
    )

    assert ok is True
    assert reason == ""
    assert parts == [
        "vsftpd_backdoor_check",
        "192.168.114.128",
        "--ftp-port",
        "21",
        "--backdoor-port",
        "6200",
        "--timeout",
        "5",
    ]


def test_validate_tool_invocation_accepts_proof_flags() -> None:
    ok, reason, parts = validate_tool_invocation(
        "vsftpd_backdoor_check",
        [
            "192.168.114.128",
            "--ftp-port",
            "21",
            "--backdoor-port",
            "6200",
            "--proof-file",
            "/tmp/tfm_ftp_21_proof.txt",
            "--proof-text",
            "I was here ftp 21",
        ],
    )

    assert ok is True
    assert reason == ""
    assert "--proof-file" in parts
    assert "--proof-text" in parts


def test_validate_tool_invocation_accepts_metasploit_search() -> None:
    ok, reason, parts = validate_tool_invocation("metasploit_search", ["vsftpd", "2.3.4", "type:exploit"])

    assert ok is True
    assert reason == ""
    assert parts == ["metasploit_search", "vsftpd", "2.3.4", "type:exploit"]


def test_validate_tool_invocation_accepts_metasploit_check_without_module_allowlist() -> None:
    ok, reason, parts = validate_tool_invocation(
        "metasploit_check",
        [
            "192.168.114.128",
            "--module",
            "exploit/unix/ftp/vsftpd_234_backdoor",
            "--rport",
            "21",
        ],
    )

    assert ok is True
    assert reason == ""
    assert parts[0] == "metasploit_check"


def test_validate_tool_invocation_accepts_metasploit_proof() -> None:
    ok, reason, parts = validate_tool_invocation(
        "metasploit_proof",
        [
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
    )

    assert ok is True
    assert reason == ""
    assert "--proof-file" in parts


def test_validate_tool_invocation_blocks_metasploit_managed_options() -> None:
    ok, reason, _ = validate_tool_invocation(
        "metasploit_check",
        [
            "192.168.114.128",
            "--module",
            "exploit/unix/misc/distcc_exec",
            "--rport",
            "3632",
            "--set",
            "RHOSTS=8.8.8.8",
        ],
    )

    assert ok is False
    assert "managed by the orchestrator" in reason


def test_metasploit_proof_requires_controlled_payload() -> None:
    result = run_metasploit_proof(
        [
            "192.168.114.128",
            "--module",
            "exploit/unix/misc/distcc_exec",
            "--rport",
            "3632",
            "--payload",
            "cmd/unix/reverse",
            "--proof-file",
            "/tmp/tfm_distccd_3632_proof.txt",
            "--proof-text",
            "I was here distccd 3632",
        ],
        "metasploit_proof 192.168.114.128",
    )

    assert result.ok is False
    assert "cmd/unix/generic" in result.output


def test_vsftpd_backdoor_check_rejects_missing_host() -> None:
    result = run_vsftpd_backdoor_check(["--ftp-port", "21"], "vsftpd_backdoor_check --ftp-port 21")

    assert result.ok is False
    assert "Expected target host" in result.output


def test_vsftpd_backdoor_check_rejects_unsafe_proof_file() -> None:
    result = run_vsftpd_backdoor_check(
        ["192.168.114.128", "--proof-file", "/root/owned.txt", "--proof-text", "I was here"],
        "vsftpd_backdoor_check 192.168.114.128 --proof-file /root/owned.txt --proof-text I was here",
    )

    assert result.ok is False
    assert "Proof file must match" in result.output


def test_tcp_shell_proof_requires_safe_proof_inputs() -> None:
    result = run_tcp_shell_proof(
        ["192.168.114.128", "--port", "1524", "--proof-file", "/tmp/tfm_bad.txt", "--proof-text", "whoami; id"],
        "tcp_shell_proof 192.168.114.128",
    )

    assert result.ok is False
    assert "Proof text" in result.output


def test_validate_tool_invocation_blocks_unknown_tool() -> None:
    ok, reason, _ = validate_tool_invocation("bash", ["-c", "whoami"])

    assert ok is False
    assert "Unknown tool" in reason
