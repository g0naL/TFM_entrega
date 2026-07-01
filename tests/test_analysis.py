from __future__ import annotations

from pentest_orchestrator.analysis import derive_finding
from pentest_orchestrator.schemas import CommandProposal, JudgeResult


def test_metasploit_proof_output_creates_proof_finding() -> None:
    proposal = CommandProposal(
        task_id="msf-proof",
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
        rationale="controlled proof",
        risk="high",
        requires_human_approval=True,
    )
    output = "\n".join(
        [
            "Metasploit module: exploit/unix/misc/distcc_exec",
            "RPORT: 3632",
            "Proof file write: CONFIRMED",
        ]
    )

    finding = derive_finding(proposal, output, JudgeResult(verdict="INCONCLUSIVE"), 0)

    assert finding is not None
    assert finding["validation_status"] == "proof_of_impact_observed"
    assert "distcc_exec" in finding["title"]


def test_metasploit_check_output_creates_validated_finding() -> None:
    proposal = CommandProposal(
        task_id="msf-check",
        phase="vulnerability_scanning",
        tool="metasploit_check",
        args=[
            "192.168.114.128",
            "--module",
            "exploit/unix/ftp/vsftpd_234_backdoor",
            "--rport",
            "21",
        ],
        rationale="controlled check",
        risk="high",
        requires_human_approval=True,
    )
    output = "\n".join(
        [
            "Metasploit module: exploit/unix/ftp/vsftpd_234_backdoor",
            "RPORT: 21",
            "[+] The target appears to be vulnerable.",
        ]
    )

    finding = derive_finding(proposal, output, JudgeResult(verdict="INCONCLUSIVE"), 0)

    assert finding is not None
    assert finding["validation_status"] == "validated_controlled"
    assert "vsftpd_234_backdoor" in finding["title"]
