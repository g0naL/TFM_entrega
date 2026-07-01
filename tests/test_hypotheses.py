from __future__ import annotations

from pentest_orchestrator.hypotheses import (
    hypothesis_from_proposal,
    merge_hypotheses,
    pending_hypotheses,
    set_hypothesis_status,
)
from pentest_orchestrator.schemas import HypothesisProposal


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


def test_hypothesis_from_proposal_creates_suspected_item() -> None:
    item = hypothesis_from_proposal(ftp_hypothesis())

    assert item["status"] == "suspected"
    assert item["required_capability"] == "ftp_behavior_validation"
    assert item["id"].startswith("21-ftp-known-vulnerable-version")


def test_merge_hypotheses_deduplicates_existing_items() -> None:
    item = hypothesis_from_proposal(ftp_hypothesis())

    merged = merge_hypotheses([item], [item])

    assert len(merged) == 1
    assert pending_hypotheses(merged) == [item]


def test_terminal_hypothesis_status_is_not_reopened_by_duplicate() -> None:
    item = hypothesis_from_proposal(ftp_hypothesis())
    closed = set_hypothesis_status([item], item["id"], "validated")

    merged = merge_hypotheses(closed, [item])

    assert merged[0]["status"] == "validated"
