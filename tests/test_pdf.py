from __future__ import annotations

from pentest_orchestrator.pdf import write_text_pdf


def test_write_text_pdf_creates_pdf_file(tmp_path) -> None:
    output = tmp_path / "report.pdf"

    write_text_pdf(output, "Pentest Lab Report", "# Resumen\n- Severity: high\nHallazgos: ninguno")

    content = output.read_bytes()
    assert content.startswith(b"%PDF-1.4")
    assert b"/Type /Catalog" in content
    assert b"/Helvetica-Bold" in content
    assert b"Page 1 / 2" in content
    assert b"Resumen" in content
