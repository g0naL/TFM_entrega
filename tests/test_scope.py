from __future__ import annotations

from pentest_orchestrator.scope import validate_target_authorized


def test_validate_target_authorized_accepts_ip_inside_lab_cidr() -> None:
    result = validate_target_authorized("192.168.114.128", "192.168.114.0/24")

    assert result.allowed is True


def test_validate_target_authorized_blocks_ip_outside_lab_cidr() -> None:
    result = validate_target_authorized("8.8.8.8", "192.168.114.0/24")

    assert result.allowed is False
    assert "outside authorized networks" in result.reason


def test_validate_target_authorized_blocks_hostnames() -> None:
    result = validate_target_authorized("example.com", "192.168.114.0/24")

    assert result.allowed is False
    assert "must be an IP address" in result.reason
