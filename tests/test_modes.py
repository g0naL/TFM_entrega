from __future__ import annotations

import json

from pentest_orchestrator.modes import load_known_vulnerabilities, normalize_campaign_mode, parse_known_vulnerabilities


def test_normalize_campaign_mode_accepts_spanish_aliases() -> None:
    assert normalize_campaign_mode("deteccion") == "detection"
    assert normalize_campaign_mode("verificación") == "verification"
    assert normalize_campaign_mode("comandos") == "command_execution"


def test_parse_known_vulnerabilities_from_json_object() -> None:
    raw = json.dumps(
        {
            "vulnerabilities": [
                {"id": "CVE-2011-2523", "title": "vsftpd backdoor"},
                "Anonymous FTP exposure",
            ]
        }
    )

    vulnerabilities = parse_known_vulnerabilities(raw)

    assert vulnerabilities == ["CVE-2011-2523 - vsftpd backdoor", "Anonymous FTP exposure"]


def test_load_known_vulnerabilities_from_text_file(tmp_path) -> None:
    path = tmp_path / "known.txt"
    path.write_text("CVE-2011-2523\nApache 2.2.8 issue\n", encoding="utf-8")

    vulnerabilities, source = load_known_vulnerabilities(path)

    assert vulnerabilities == ["CVE-2011-2523", "Apache 2.2.8 issue"]
    assert source == str(path)
