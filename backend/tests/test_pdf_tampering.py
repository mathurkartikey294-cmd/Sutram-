"""Unit tests for native PDF structural tampering detection."""

from pathlib import Path

try:
    from app.detectors.base import CalibratedScale
    from app.detectors.registry import detector_registry
    from app.provenance.pdf_document import NativePDFForensicsDetector
except ImportError:
    from backend.app.detectors.base import CalibratedScale
    from backend.app.detectors.registry import detector_registry
    from backend.app.provenance.pdf_document import NativePDFForensicsDetector

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _pdf_literal(value: str) -> bytes:
    escaped = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return b"(" + escaped.encode("latin-1") + b")"


def _stream(extra_dictionary: bytes, data: bytes) -> bytes:
    dictionary = b"<< " + extra_dictionary + b" /Length " + str(len(data)).encode() + b" >>"
    return dictionary + b"\nstream\n" + data + b"\nendstream"


def _info(producer: str, creation: str, modification: str) -> bytes:
    return (
        b"<< /Producer "
        + _pdf_literal(producer)
        + b" /Creator "
        + _pdf_literal("SUTRAM Test Generator")
        + b" /CreationDate "
        + _pdf_literal(creation)
        + b" /ModDate "
        + _pdf_literal(modification)
        + b" >>"
    )


def _build_pdf(
    objects: list[bytes],
    *,
    info_number: int,
    trailer_extra: bytes = b"",
) -> tuple[bytes, int]:
    pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_offset = len(pdf)
    pdf += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n"
    pdf += b"0000000000 65535 f \n"
    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode()
    pdf += (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode()
        + b" /Root 1 0 R /Info "
        + str(info_number).encode()
        + b" 0 R"
        + trailer_extra
        + b" >>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return pdf, xref_offset


def _clean_pdf(
    *,
    producer: str = "SUTRAM Test Suite",
    creation: str = "D:20240101120000Z",
    modification: str = "D:20240101130000Z",
    linearized: bool = False,
    content: bytes = b"BT /F1 12 Tf 72 720 Td (Authentic invoice total 10000) Tj ET",
    include_unembedded_font: bool = False,
) -> tuple[bytes, int]:
    catalog = b"<< /Type /Catalog /Pages 2 0 R"
    if linearized:
        catalog += b" /Linearized 1 /L 2048"
    catalog += b" >>"

    page_fonts = b"/F1 5 0 R"
    if include_unembedded_font:
        page_fonts += b" /F2 8 0 R"
        info_number = 9
    else:
        info_number = 8

    objects: list[bytes] = [
        catalog,
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << " + page_fonts + b" >> >> /Contents 4 0 R >>"
        ),
        _stream(b"", content),
        (b"<< /Type /Font /Subtype /TrueType /BaseFont /XYZABC+ArialMT /FontDescriptor 6 0 R >>"),
        (
            b"<< /Type /FontDescriptor /FontName /XYZABC+ArialMT /Flags 32 "
            b"/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent -200 "
            b"/CapHeight 700 /StemV 80 /FontFile2 7 0 R >>"
        ),
        _stream(b"/Length1 8", b"FAKEFONT"),
    ]
    if include_unembedded_font:
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(_info(producer, creation, modification))
    return _build_pdf(objects, info_number=info_number)


def _append_revision(base: bytes, base_xref_offset: int) -> bytes:
    updated_info = _info("PDFtk Server 2.02", "D:20240101120000Z", "D:20250901120000Z")
    info_offset = len(base)
    pdf = base + b"9 0 obj\n" + updated_info + b"\nendobj\n"
    xref_offset = len(pdf)
    pdf += b"xref\n9 1\n" + f"{info_offset:010d} 00000 n \n".encode()
    pdf += (
        b"trailer\n<< /Size 10 /Root 1 0 R /Info 9 0 R /Prev "
        + str(base_xref_offset).encode()
        + b" >>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return pdf


def _analyze(tmp_path: Path, data: bytes, evidence_id: str):
    pdf_path = tmp_path / f"{evidence_id}.pdf"
    pdf_path.write_bytes(data)
    return NativePDFForensicsDetector().analyze(pdf_path, {"evidence_id": evidence_id})


def _metric(result, name: str):
    for item in result.evidence:
        if item.description == name:
            return item.value
    raise AssertionError(f"missing evidence metric {name}")


def test_clean_single_revision_pdf(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf()
    result = _analyze(tmp_path, pdf, "clean_pdf")

    assert result.status == "ok"
    assert _metric(result, "revision_count") == 1
    assert _metric(result, "incremental_updates_detected") is False
    assert result.score <= 0.20
    assert result.verbal_verdict == CalibratedScale.STRONGLY_AUTHENTIC.value
    assert result.artifacts == []


def test_incremental_update_is_flagged_and_original_extracted(tmp_path: Path) -> None:
    base, base_xref = _clean_pdf()
    updated = _append_revision(base, base_xref)
    result = _analyze(tmp_path, updated, "incremental_pdf")

    assert result.status == "ok"
    assert _metric(result, "revision_count") == 2
    assert _metric(result, "incremental_updates_detected") is True
    assert result.score >= 0.60
    assert result.verbal_verdict in {
        CalibratedScale.SUPPORTS_MANIPULATION.value,
        CalibratedScale.STRONGLY_MANIPULATION.value,
    }
    assert result.artifacts
    assert result.artifacts[0].endswith("incremental_pdf_revision_1.pdf")

    artifact_path = _REPO_ROOT / result.artifacts[0]
    try:
        assert artifact_path.exists()
        assert artifact_path.read_bytes() == base
    finally:
        artifact_path.unlink(missing_ok=True)


def test_minimal_pdf_without_startxref_is_still_single_revision(tmp_path: Path) -> None:
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
    result = _analyze(tmp_path, pdf, "minimal_pdf")

    assert result.status == "ok"
    assert _metric(result, "revision_count") == 1
    assert _metric(result, "incremental_updates_detected") is False
    assert result.score <= 0.20


def test_linearized_pdf_does_not_trigger_false_positive(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(linearized=True)
    result = _analyze(tmp_path, pdf, "linearized_pdf")

    assert result.status == "ok"
    assert _metric(result, "revision_count") == 1
    assert _metric(result, "incremental_updates_detected") is False
    assert result.score <= 0.20
    assert any(item.description == "linearized_pdf" for item in result.evidence)
    assert result.verbal_verdict == CalibratedScale.STRONGLY_AUTHENTIC.value


def test_linearized_extra_eof_remains_benign(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(linearized=True)
    result = _analyze(tmp_path, pdf + b"%%EOF\n", "linearized_extra_eof")

    assert _metric(result, "revision_count") == 1
    assert _metric(result, "incremental_updates_detected") is False
    assert result.score <= 0.20


def test_suspicious_producer_signature_is_reported(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(producer="PDFtk Server 2.02")
    result = _analyze(tmp_path, pdf, "suspicious_producer")

    assert result.status == "ok"
    warning = next(
        (
            item
            for item in result.evidence
            if item.description == "Suspicious Producer or Creator software signature"
        ),
        None,
    )
    assert warning is not None
    assert "pdftk" in warning.value["matched_signatures"]
    assert warning.value["producer"] == "PDFtk Server 2.02"
    assert "Editing software signatures" in result.summary


def test_corrupt_and_non_pdf_input_is_safe(tmp_path: Path) -> None:
    non_pdf = _analyze(tmp_path, b"this is definitely not a PDF", "not_a_pdf")
    assert non_pdf.status == "error"
    assert non_pdf.score == 0.5
    assert non_pdf.verbal_verdict == CalibratedScale.INCONCLUSIVE.value
    assert non_pdf.limitations

    truncated = _analyze(
        tmp_path, b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n", "truncated_pdf"
    )
    assert truncated.status == "error"
    assert truncated.score == 0.5
    assert truncated.verbal_verdict == CalibratedScale.INCONCLUSIVE.value


def test_registry_discovers_native_pdf_detector() -> None:
    registered = detector_registry.get("native_pdf_forensics")
    assert isinstance(registered, NativePDFForensicsDetector)
    assert registered.version == "1.0.0"
    assert registered.category == "tampering"
    assert "application/pdf" in registered.supported_media_types


def test_encrypted_pdf_is_inconclusive(tmp_path: Path) -> None:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        _info("SUTRAM Test Suite", "D:20240101120000Z", "D:20240101130000Z"),
    ]
    pdf, _ = _build_pdf(objects, info_number=4, trailer_extra=b" /Encrypt 9 0 R")
    result = _analyze(tmp_path, pdf, "encrypted_pdf")

    assert result.status == "skipped"
    assert result.score == 0.5
    assert result.verbal_verdict == CalibratedScale.INCONCLUSIVE.value
    assert any("encrypted" in limitation.lower() for limitation in result.limitations)


def test_mixed_font_embedding_is_reported(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(include_unembedded_font=True)
    result = _analyze(tmp_path, pdf, "font_inconsistency")

    assert result.status == "ok"
    assert _metric(result, "font_inconsistency_count") >= 1
    font_item = next(
        (item for item in result.evidence if "Font stream inconsistency" in item.description),
        None,
    )
    assert font_item is not None
    assert font_item.value["affected_pages"] == [1]
    assert {font["base_font"] for font in font_item.value["fonts"]} == {
        "XYZABC+ArialMT",
        "Helvetica",
    }
    assert result.score > 0.40


def test_invisible_text_layer_is_reported(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(
        content=b"BT /F1 12 Tf 72 720 Td 3 Tr (Hidden OCR layer) Tj ET",
    )
    result = _analyze(tmp_path, pdf, "invisible_text")

    assert result.status == "ok"
    invisible = next(
        (item for item in result.evidence if item.description == "invisible_text_layer"),
        None,
    )
    assert invisible is not None
    assert invisible.value["streams_with_3_Tr"] == 1
    assert invisible.value["visual_representation_missing"] is True
    assert invisible.value["potential_ocr_visual_discrepancy"] is True
    assert result.parameters_used["potential_ocr_visual_discrepancy"] is True
    assert any("Invisible text" in limitation for limitation in result.limitations)


def test_appended_eof_without_trailer_still_counts_as_revision(tmp_path: Path) -> None:
    base, _ = _clean_pdf()
    appended = base + b"9 0 obj\n<< /Tampered true >>\nendobj\n%%EOF\n"
    result = _analyze(tmp_path, appended, "appended_eof")

    assert _metric(result, "revision_count") == 2
    assert _metric(result, "incremental_updates_detected") is True
    assert result.score >= 0.60
    assert result.artifacts

    artifact_path = _REPO_ROOT / result.artifacts[0]
    try:
        assert artifact_path.read_bytes() == base
    finally:
        artifact_path.unlink(missing_ok=True)


def test_eof_text_inside_stream_is_not_counted_as_revision(tmp_path: Path) -> None:
    pdf, _ = _clean_pdf(
        content=b"BT /F1 12 Tf 72 720 Td (Report footer %%EOF marker) Tj ET",
    )
    result = _analyze(tmp_path, pdf, "stream_eof_text")

    assert _metric(result, "revision_count") == 1
    assert _metric(result, "incremental_updates_detected") is False
    assert result.score <= 0.20
