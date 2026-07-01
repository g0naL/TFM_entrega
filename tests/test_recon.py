from __future__ import annotations

from pentest_orchestrator.recon import detect_metasploitable_hints, parse_nmap_services


NMAP_SAMPLE = """
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
"""


def test_parse_nmap_services_extracts_port_table() -> None:
    services = parse_nmap_services(NMAP_SAMPLE)

    assert services == [
        {
            "port": 21,
            "proto": "tcp",
            "state": "open",
            "service": "ftp",
            "version_line": "vsftpd 2.3.4",
        },
        {
            "port": 80,
            "proto": "tcp",
            "state": "open",
            "service": "http",
            "version_line": "Apache httpd 2.2.8 ((Ubuntu) DAV/2)",
        },
        {
            "port": 3306,
            "proto": "tcp",
            "state": "open",
            "service": "mysql",
            "version_line": "MySQL 5.0.51a-3ubuntu5",
        },
    ]


def test_detect_metasploitable_hints_is_case_insensitive() -> None:
    hints = detect_metasploitable_hints(NMAP_SAMPLE)

    assert "vsftpd" in hints
    assert "mysql" in hints
