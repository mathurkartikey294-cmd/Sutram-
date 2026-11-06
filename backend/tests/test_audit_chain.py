"""
Unit tests for SUTRAM's RFC 8785 canonical JSON and tamper-evident audit chain.

These tests encode the evidentiary guarantees required by ISO/IEC 27037 and
Bharatiya Sakshya Adhiniyam 2023 Section 63: deterministic serialization,
cross-platform hash reproducibility, append-only ordering, and detection of
any direct database alteration, deletion, or reordering.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import create_engine, delete, func, select, update
from sqlalchemy.orm import Session, sessionmaker

try:
    from app.core.audit import (
        AuditVerificationResult,
        get_case_audit_log,
        record_audit_event,
        verify_case_audit_chain,
    )
    from app.core.signing import (
        GENESIS_HASH,
        canonical_json_bytes,
        canonical_json_hash,
        compute_entry_hash,
    )
    from app.db.models import AuditEntry, Base, Case
except ImportError:
    from backend.app.core.audit import (
        AuditVerificationResult,
        get_case_audit_log,
        record_audit_event,
        verify_case_audit_chain,
    )
    from backend.app.core.signing import (
        GENESIS_HASH,
        canonical_json_bytes,
        canonical_json_hash,
        compute_entry_hash,
    )
    from backend.app.db.models import AuditEntry, Base, Case


@pytest.fixture
def db_session() -> Iterator[Session]:
    """Create a fresh in-memory SQLite database for every test."""

    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, expire_on_commit=False)
    session = testing_session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed_case(session: Session, case_id: str) -> Case:
    case = Case(
        id=case_id,
        title=f"Investigation {case_id}",
        description="Audit chain regression fixture",
        created_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=UTC),
        status="open",
    )
    session.add(case)
    session.flush()
    return case


def _append_chain(session: Session, case_id: str = "case-a", count: int = 5) -> list[AuditEntry]:
    if session.get(Case, case_id) is None:
        _seed_case(session, case_id)

    entries: list[AuditEntry] = []
    for index in range(count):
        entry = record_audit_event(
            session,
            case_id=case_id,
            actor="examiner:kartikey",
            action="analysis_start",
            target_type="evidence",
            target_id=f"ev-{index:03d}",
            details={
                "sequence": index,
                "note": "सूत्रम् 🔒",
                "path": "C:\\evidence\\file with spaces.jpg",
            },
            timestamp_utc=datetime(2026, 1, 1, 12, 0, index, tzinfo=UTC),
        )
        entries.append(entry)
    session.commit()
    return entries


def _update_entry(session: Session, entry_id: int, **values: Any) -> None:
    session.execute(update(AuditEntry).where(AuditEntry.id == entry_id).values(**values))
    session.commit()


def _entry_values_without_id(entry: AuditEntry) -> dict[str, Any]:
    return {
        column.name: getattr(entry, column.name)
        for column in AuditEntry.__table__.columns
        if column.name != "id"
    }


def test_canonical_json_key_sorting() -> None:
    first = {"b": 2, "a": 1}
    second = {"a": 1, "b": 2}

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert canonical_json_bytes(first) == b'{"a":1,"b":2}'


def test_canonical_json_no_whitespace() -> None:
    encoded = canonical_json_bytes({"b": {"c": 3}, "a": [1, 2]})

    assert encoded == b'{"a":[1,2],"b":{"c":3}}'
    assert b" " not in encoded
    assert b"\n" not in encoded
    assert b"\t" not in encoded


def test_canonical_json_numeric_string_sort_order() -> None:
    encoded = canonical_json_bytes({"2": 2, "10": 10, "1": 1})

    assert encoded == b'{"1":1,"10":10,"2":2}'


def test_canonical_json_nested_objects_sorted_recursively() -> None:
    first = {"z": {"b": 2, "a": 1}, "a": [{"y": 2, "x": 1}, 3, 1, 2]}
    second = {"a": [{"x": 1, "y": 2}, 3, 1, 2], "z": {"a": 1, "b": 2}}

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert canonical_json_bytes({"a": [3, 1, 2]}) == b'{"a":[3,1,2]}'


def test_canonical_json_unicode_hindi_emoji() -> None:
    encoded = canonical_json_bytes({"hindi": "सूत्रम्", "emoji": "🔒", "mixed": "A सूत्रम् 🔒"})

    assert not encoded.startswith(b"\xef\xbb\xbf")
    assert "सूत्रम्".encode() in encoded
    assert "🔒".encode() in encoded
    assert encoded.decode("utf-8") == '{"emoji":"🔒","hindi":"सूत्रम्","mixed":"A सूत्रम् 🔒"}'


def test_canonical_json_escapes_only_mandatory_characters() -> None:
    encoded = canonical_json_bytes({"text": 'a\x01b\nc"d\\e/f'})

    assert encoded == b'{"text":"a\\u0001b\\nc\\"d\\\\e/f"}'


def test_canonical_json_handles_explicit_surrogate_pairs() -> None:
    encoded = canonical_json_bytes({"lock": "\ud83d\udd12"})

    assert encoded == b'{"lock":"\\ud83d\\udd12"}'


def test_canonical_json_empty_containers() -> None:
    assert canonical_json_bytes({}) == b"{}"
    assert canonical_json_bytes([]) == b"[]"
    assert canonical_json_hash({}) == hashlib.sha256(b"{}").hexdigest()
    assert canonical_json_hash([]) == hashlib.sha256(b"[]").hexdigest()


def test_canonical_json_none_serializes_as_null() -> None:
    assert canonical_json_bytes(None) == b"null"
    assert canonical_json_bytes({"value": None}) == b'{"value":null}'


def test_canonical_json_datetime_converted() -> None:
    aware = datetime(2026, 2, 3, 4, 5, 6, 789012, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    normalized = aware.astimezone(UTC).isoformat()
    naive = datetime(2026, 2, 3, 4, 5, 6)

    assert canonical_json_bytes({"t": aware}) == canonical_json_bytes({"t": normalized})
    assert canonical_json_bytes({"t": naive}) == canonical_json_bytes(
        {"t": naive.replace(tzinfo=UTC).isoformat()}
    )


def test_canonical_json_rejects_nan_inf() -> None:
    for invalid in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_json_bytes({"value": invalid})
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": Decimal("1.5")})


def test_canonical_json_rejects_bytes() -> None:
    with pytest.raises(TypeError):
        canonical_json_bytes({"blob": b"\x00\x01"})
    with pytest.raises(TypeError):
        canonical_json_bytes({"blob": bytearray(b"\x00\x01")})


def test_canonical_json_deeply_nested() -> None:
    nested: Any = "leaf"
    for _ in range(40):
        nested = {"level": nested}

    encoded = canonical_json_bytes(nested)

    assert encoded.startswith(b'{"level":')
    assert canonical_json_hash(nested) == hashlib.sha256(encoded).hexdigest()


def test_canonical_json_deterministic_across_calls() -> None:
    payload = {
        "case_id": "case-🔒",
        "details": {"note": "सूत्रम्", "values": [1, 2, 3, {"nested": True}]},
        "timestamp_utc": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    }

    hashes = {canonical_json_hash(payload) for _ in range(1000)}

    assert len(hashes) == 1


def test_compute_entry_hash_binds_prev_hash() -> None:
    payload = {
        "case_id": "case-a",
        "timestamp_utc": "2026-01-01T12:00:00+00:00",
        "actor": "examiner:kartikey",
        "action": "ingest",
        "target_type": "evidence",
        "target_id": "ev-001",
        "details": {},
    }

    genesis_hash = compute_entry_hash(payload, GENESIS_HASH)
    other_hash = compute_entry_hash(payload, "1" * 64)

    assert (
        genesis_hash
        == hashlib.sha256(canonical_json_bytes(payload) + GENESIS_HASH.encode()).hexdigest()
    )
    assert genesis_hash != other_hash


def test_genesis_entry_uses_genesis_hash(db_session: Session) -> None:
    entries = _append_chain(db_session, count=1)

    assert entries[0].prev_hash == GENESIS_HASH
    assert verify_case_audit_chain(db_session, "case-a").valid


def test_second_entry_chains_to_first(db_session: Session) -> None:
    entries = _append_chain(db_session, count=2)

    assert entries[1].prev_hash == entries[0].current_hash
    assert verify_case_audit_chain(db_session, "case-a").valid


def test_chain_of_five_entries_verifies_valid(db_session: Session) -> None:
    _append_chain(db_session, count=5)

    result = verify_case_audit_chain(db_session, "case-a")

    assert result == AuditVerificationResult(
        valid=True,
        total_entries=5,
        verified_entries=5,
    )


def test_tamper_action_field_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(db_session, entries[2].id, action="records_deleted")

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == entries[2].id
    assert result.reason is not None
    assert "current_hash mismatch" in result.reason


def test_tamper_details_field_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(db_session, entries[2].id, details={"sequence": 2, "note": "forged"})

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == entries[2].id


def test_tamper_timestamp_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(
        db_session,
        entries[2].id,
        timestamp_utc=datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC),
    )

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == entries[2].id


def test_tamper_current_hash_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(db_session, entries[2].id, current_hash="f" * 64)

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == entries[2].id
    assert result.reason is not None
    assert "current_hash mismatch" in result.reason


def test_tamper_prev_hash_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(db_session, entries[1].id, prev_hash="f" * 64)

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == entries[1].id
    assert result.reason is not None
    assert "prev_hash mismatch" in result.reason


def test_delete_middle_entry_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    db_session.execute(delete(AuditEntry).where(AuditEntry.id == entries[2].id))
    db_session.commit()

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.total_entries == 4
    assert result.verified_entries == 2
    assert result.tampered_entry_id == entries[3].id
    assert result.tampered_entry_index == 2
    assert result.reason is not None
    assert "prev_hash mismatch" in result.reason


def test_swap_entries_detected(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    left, right = entries[1], entries[2]
    left_values = _entry_values_without_id(left)
    right_values = _entry_values_without_id(right)

    db_session.execute(update(AuditEntry).where(AuditEntry.id == left.id).values(**right_values))
    db_session.execute(update(AuditEntry).where(AuditEntry.id == right.id).values(**left_values))
    db_session.commit()

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.tampered_entry_id == left.id
    assert result.tampered_entry_index == 1


def test_empty_chain_is_valid(db_session: Session) -> None:
    result = verify_case_audit_chain(db_session, "case-with-no-entries")

    assert result == AuditVerificationResult(
        valid=True,
        total_entries=0,
        verified_entries=0,
    )


def test_multi_case_isolation(db_session: Session) -> None:
    case_a_entries = _append_chain(db_session, case_id="case-a", count=5)
    _append_chain(db_session, case_id="case-b", count=5)
    _update_entry(db_session, case_a_entries[2].id, action="forged")

    result_a = verify_case_audit_chain(db_session, "case-a")
    result_b = verify_case_audit_chain(db_session, "case-b")

    assert not result_a.valid
    assert result_b.valid
    assert result_b.total_entries == 5


def test_unicode_in_details_hashes_correctly(db_session: Session) -> None:
    _seed_case(db_session, "case-a")
    record_audit_event(
        db_session,
        case_id="case-a",
        actor="examiner:kartikey",
        action="ingest",
        target_type="evidence",
        target_id="ev-सूत्रम्-001",
        details={
            "हिंदी": "सूत्रम्",
            "emoji": "🔒",
            "path": "C:\\evidence\\file with spaces.jpg",
        },
        timestamp_utc=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    db_session.commit()

    result = verify_case_audit_chain(db_session, "case-a")

    assert result.valid


def test_large_details_payload(db_session: Session) -> None:
    _seed_case(db_session, "case-a")
    details = {
        f"key_{index:02d}": {
            "index": index,
            "values": [index, index + 1, {"nested": "सूत्रम् 🔒"}],
        }
        for index in range(60)
    }
    record_audit_event(
        db_session,
        case_id="case-a",
        actor="examiner:kartikey",
        action="analysis_start",
        target_type="evidence",
        target_id="ev-large",
        details=details,
        timestamp_utc=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    db_session.commit()

    result = verify_case_audit_chain(db_session, "case-a")

    assert result.valid


def test_record_event_does_not_commit(db_session: Session) -> None:
    _seed_case(db_session, "case-a")
    db_session.commit()

    entry = record_audit_event(
        db_session,
        case_id="case-a",
        actor="examiner:kartikey",
        action="ingest",
        target_type="evidence",
        target_id="ev-001",
    )

    assert entry.id is not None
    assert db_session.in_transaction()

    db_session.rollback()

    assert db_session.scalar(select(func.count()).select_from(AuditEntry)) == 0


def test_verification_result_reports_exact_tampered_entry(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)
    _update_entry(db_session, entries[2].id, actor="examiner:unknown")

    result = verify_case_audit_chain(db_session, "case-a")

    assert not result.valid
    assert result.total_entries == 5
    assert result.verified_entries == 2
    assert result.tampered_entry_id == entries[2].id
    assert result.tampered_entry_index == 2


def test_get_case_audit_log_pagination(db_session: Session) -> None:
    entries = _append_chain(db_session, count=5)

    page = get_case_audit_log(db_session, "case-a", limit=2, offset=1)
    remainder = get_case_audit_log(db_session, "case-a", limit=None, offset=3)

    assert [entry.id for entry in page] == [entries[1].id, entries[2].id]
    assert [entry.id for entry in remainder] == [entries[3].id, entries[4].id]
    assert get_case_audit_log(db_session, "case-a", limit=2, offset=99) == []


def test_naive_datetime_handling(db_session: Session) -> None:
    _seed_case(db_session, "case-a")
    naive = datetime(2026, 3, 1, 10, 30, 0)

    entry = record_audit_event(
        db_session,
        case_id="case-a",
        actor="examiner:kartikey",
        action="verify_hash",
        target_type="evidence",
        target_id="ev-naive",
        timestamp_utc=naive,
    )
    db_session.commit()

    assert entry.timestamp_utc == naive.replace(tzinfo=UTC)
    assert entry.prev_hash == GENESIS_HASH
    assert verify_case_audit_chain(db_session, "case-a").valid
