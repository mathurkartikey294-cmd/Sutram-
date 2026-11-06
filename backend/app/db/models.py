"""
SQLAlchemy 2.0 persistence models for SUTRAM.

Forensic WHY: Cases, evidence, and audit entries must be stored in a relational
ledger that can be exported, reviewed, and independently re-verified. The audit
table deliberately stores both the previous and current SHA-256 chain hashes so
a later alteration of any row is detectable without trusting application memory.
Timestamps are recorded in UTC to keep cross-jurisdiction timelines consistent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base shared by every SUTRAM database model."""


class Case(Base):
    """An investigation container grouping evidence and audit history."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")


class Evidence(Base):
    """An immutable exhibit registered against a case."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("cases.id"),
        nullable=False,
        index=True,
    )
    original_path: Mapped[str] = mapped_column(Text, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)


class AuditEntry(Base):
    """
    One link in a case-specific, tamper-evident hash chain.

    ``details`` uses a mutable JSON wrapper so in-place edits are tracked by
    SQLAlchemy; any such edit will no longer match the hash recorded at append
    time. The row is never updated by the application after insertion.
    """

    __tablename__ = "audit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("cases.id"),
        index=True,
        nullable=False,
    )
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
