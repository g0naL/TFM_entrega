from __future__ import annotations

from pentest_orchestrator.capabilities import (
    resolve_executable,
    resolve_git_bash,
    resolve_local_tool,
    resolve_msfconsole,
    tool_available,
)


def test_resolve_tool_from_specific_env_path(tmp_path, monkeypatch) -> None:
    tool = tmp_path / "nuclei.exe"
    tool.write_text("", encoding="utf-8")
    monkeypatch.setenv("PENTEST_NUCLEI_PATH", str(tool))

    assert resolve_executable("nuclei") == str(tool)


def test_resolve_tool_from_tools_dir(tmp_path, monkeypatch) -> None:
    tool_dir = tmp_path / "tools" / "ffuf"
    tool_dir.mkdir(parents=True)
    tool = tool_dir / "ffuf.exe"
    tool.write_text("", encoding="utf-8")
    monkeypatch.setenv("PENTEST_TOOLS_DIR", str(tmp_path / "tools"))

    assert resolve_local_tool("ffuf") == str(tool)


def test_resolve_git_bash_from_env(tmp_path, monkeypatch) -> None:
    bash = tmp_path / "bash.exe"
    bash.write_text("", encoding="utf-8")
    monkeypatch.setenv("PENTEST_BASH_PATH", str(bash))

    assert resolve_git_bash() == str(bash)


def test_resolve_msfconsole_from_env(tmp_path, monkeypatch) -> None:
    msfconsole = tmp_path / "msfconsole.bat"
    msfconsole.write_text("", encoding="utf-8")
    monkeypatch.setenv("PENTEST_MSFCONSOLE_PATH", str(msfconsole))

    assert resolve_msfconsole() == str(msfconsole)
    assert tool_available("metasploit_search") is True


def test_builtin_vsftpd_check_is_available() -> None:
    assert tool_available("vsftpd_backdoor_check") is True


def test_builtin_tcp_shell_proof_is_available() -> None:
    assert tool_available("tcp_shell_proof") is True
