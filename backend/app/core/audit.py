"""
Tamper-evident audit chaining for SUTRAM.

Forensic WHY: Every investigative action must be attributable and immutable in
practice. Each audit row stores a SHA-256 hash over its own canonical fields
bound to the previous row's hash, so altering, deleting, inserting, or
reordering a row breaks verification from that point forward. Verification
recomputes hashes from the database columns rather than trusting cached ORM
state, and compares digests in constant time to avoid timing side channels.
"""

from __future__ import annotations

import copy
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AuditEntry
from .signing import GENESIS_HASH, compute_entry_hash, normalize_utc


@dataclass(frozen=True, slots=True)
class AuditVerificationResult:
    """Outcome of re-deriving a case's complete audit hash chain."""

    valid: bool
    total_entries: int
    verified_entries: int
    tampered_entry_id: int | None = None
    tampered_entry_index: int | None = None
    reason: str | None = None


def _build_payload(entry: AuditEntry) -> dict[str, Any]:
    timestamp = entry.timestamp_utc
    if not isinstance(timestamp, datetime):
        raise TypeError("timestamp_utc is not a datetime")
    details = entry.details
    if details is None:
        raise TypeError("details column is NULL")
    return {
        "case_id": entry.case_id,
        "timestamp_utc": normalize_utc(timestamp).isoformat(),
        "actor": entry.actor,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": details,
    }


def _latest_entry(session: Session, case_id: str) -> AuditEntry | None:
    statement = (
        select(AuditEntry)
        .where(AuditEntry.case_id == case_id)
        .order_by(AuditEntry.id.desc())
        .limit(1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return session.scalars(statement).first()


def record_audit_event(
    session: Session,
    *,
    case_id: str,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any] | None = None,
    timestamp_utc: datetime | None = None,
) -> AuditEntry:
    """
    Append a new hash-linked entry to a case's audit chain.

    The caller owns the transaction boundary: this function flushes so the
    entry receives its primary key, but never commits. Evidence ingest and its
    audit witness can therefore succeed or roll back as one atomic action.
    SQLite serializes writers; ``with_for_update`` additionally guards the
    latest-row read on engines that support row locks.
    """

    timestamp = normalize_utc(timestamp_utc) if timestamp_utc is not None else datetime.now(UTC)
    details_snapshot: dict[str, Any] = copy.deepcopy(details) if details is not None else {}

    last_entry = _latest_entry(session, case_id)
    prev_hash = last_entry.current_hash if last_entry is not None else GENESIS_HASH

    payload: dict[str, Any] = {
        "case_id": case_id,
        "timestamp_utc": timestamp.isoformat(),
        "actor": actor,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "details": details_snapshot,
    }

    entry = AuditEntry(
        case_id=case_id,
        timestamp_utc=timestamp,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details_snapshot,
        prev_hash=prev_hash,
        current_hash=compute_entry_hash(payload, prev_hash),
    )
    session.add(entry)
    session.flush()
    return entry


def verify_case_audit_chain(session: Session, case_id: str) -> AuditVerificationResult:
    """
    Re-derive every hash in a case's chain and report the first broken link.

    Rows are reloaded with ``populate_existing`` so verification reflects the
    database, not potentially stale identity-map values left in the session.
    """

    statement = (
        select(AuditEntry)
        .where(AuditEntry.case_id == case_id)
        .order_by(AuditEntry.id.asc())
        .execution_options(populate_existing=True)
    )
    entries = list(session.scalars(statement).all())
    total_entries = len(entries)

    if not entries:
        return AuditVerificationResult(valid=True, total_entries=0, verified_entries=0)

    expected_prev_hash = GENESIS_HASH
    for index, entry in enumerate(entries):
        if not isinstance(entry.prev_hash, str) or not isinstance(entry.current_hash, str):
            return AuditVerificationResult(
                valid=False,
                total_entries=total_entries,
                verified_entries=index,
                tampered_entry_id=entry.id,
                tampered_entry_index=index,
                reason=f"hash columns missing or non-text at entry id={entry.id}",
            )

        try:
            payload = _build_payload(entry)
            expected_hash = compute_entry_hash(payload, expected_prev_hash)
        except (TypeError, ValueError) as exc:
            return AuditVerificationResult(
                valid=False,
                total_entries=total_entries,
                verified_entries=index,
                tampered_entry_id=entry.id,
                tampered_entry_index=index,
                reason=f"payload could not be canonicalized at entry id={entry.id}: {exc}",
            )

        if not hmac.compare_digest(entry.prev_hash, expected_prev_hash):
            return AuditVerificationResult(
                valid=False,
                total_entries=total_entries,
                verified_entries=index,
                tampered_entry_id=entry.id,
                tampered_entry_index=index,
                reason=f"prev_hash mismatch at entry id={entry.id} (index {index})",
            )

        if not hmac.compare_digest(entry.current_hash, expected_hash):
            return AuditVerificationResult(
                valid=False,
                total_entries=total_entries,
                verified_entries=index,
                tampered_entry_id=entry.id,
                tampered_entry_index=index,
                reason=f"current_hash mismatch at entry id={entry.id} (index {index})",
            )

        expected_prev_hash = entry.current_hash

    return AuditVerificationResult(
        valid=True,
        total_entries=total_entries,
        verified_entries=total_entries,
    )


def get_case_audit_log(
    session: Session,
    case_id: str,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[AuditEntry]:
    """Return a case's audit entries in append order with optional pagination."""

    if offset < 0:
        raise ValueError("offset must be zero or greater")
    if limit is not None and limit < 0:
        raise ValueError("limit must be zero or greater")

    statement = (
        select(AuditEntry)
        .where(AuditEntry.case_id == case_id)
        .order_by(AuditEntry.id.asc())
        .offset(offset)
        .execution_options(populate_existing=True)
    )
    if limit is not None:
        statement = statement.limit(limit)
    return list(session.scalars(statement).all())
