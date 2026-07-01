from __future__ import annotations

import pytest
from pydantic import ValidationError

from pentest_orchestrator.schemas import CommandProposal, HypothesisResult, JudgeResult


def test_command_proposal_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        CommandProposal.model_validate(
            {
                "action_type": "RUN_COMMAND",
                "tool": "nmap",
                "args": ["-sV", "192.168.114.128"],
                "rationale": "safe enum",
                "risk": "low",
                "requires_human_approval": False,
                "command": "nmap -sV 192.168.114.128",
            }
        )


def test_command_proposal_rejects_invalid_risk() -> None:
    with pytest.raises(ValidationError):
        CommandProposal.model_validate(
            {
                "action_type": "RUN_COMMAND",
                "tool": "nmap",
                "args": ["-sV", "192.168.114.128"],
                "rationale": "safe enum",
                "risk": "banana",
                "requires_human_approval": False,
            }
        )


def test_judge_result_rejects_invalid_verdict() -> None:
    with pytest.raises(ValidationError):
        JudgeResult.model_validate({"verdict": "MAYBE", "why": "unclear"})


def test_high_risk_tool_forces_risk_and_approval() -> None:
    proposal = CommandProposal.model_validate(
        {
            "action_type": "RUN_COMMAND",
            "tool": "hydra",
            "args": ["-l", "user", "-P", "wordlist.txt", "ssh://192.168.114.128"],
            "rationale": "lab credential validation",
            "risk": "low",
            "requires_human_approval": False,
        }
    )

    assert proposal.risk == "high"
    assert proposal.requires_human_approval is True


def test_hypothesis_result_rejects_commands_and_unknown_capabilities() -> None:
    with pytest.raises(ValidationError):
        HypothesisResult.model_validate(
            {
                "summary": "bad hypothesis",
                "hypotheses": [
                    {
                        "service_port": 21,
                        "service_name": "ftp",
                        "observed_evidence": "vsFTPd 2.3.4",
                        "weakness_class": "known_vulnerable_version",
                        "hypothesis": "FTP service may expose unsafe behavior.",
                        "validation_strategy": "validate behavior in a controlled way",
                        "required_capability": "raw_shell_command",
                        "confidence": "medium",
                        "risk": "high",
                        "rationale": "banner suggests a known issue",
                        "args": ["192.168.114.128"],
                    }
                ],
            }
        )


def test_hypothesis_result_accepts_abstract_capability() -> None:
    result = HypothesisResult.model_validate(
        {
            "summary": "ftp hypothesis",
            "hypotheses": [
                {
                    "service_port": 21,
                    "service_name": "ftp",
                    "observed_evidence": "vsFTPd 2.3.4",
                    "weakness_class": "known_vulnerable_version",
                    "hypothesis": "FTP service may expose documented unsafe behavior.",
                    "validation_strategy": "perform controlled behavioral validation without free-form commands",
                    "required_capability": "ftp_behavior_validation",
                    "confidence": "high",
                    "risk": "high",
                    "rationale": "exact FTP banner supports a hypothesis worth validating",
                }
            ],
        }
    )

    assert result.hypotheses[0].required_capability == "ftp_behavior_validation"
