"""
Database engine and session factory for SUTRAM.

Forensic WHY: Evidence metadata and the audit ledger must remain on the local
air-gapped host. The default URL therefore points at SQLite inside
``evidence_store/`` rather than any remote service. Callers explicitly control
transaction boundaries; audit entries are flushed alongside the evidence they
describe and committed only when the examiner's action succeeds atomically.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_DB_PATH = _REPO_ROOT / "evidence_store" / "sutram.db"


def get_database_url() -> str:
    """Return the configured database URL, defaulting to local SQLite."""

    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    _DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{_DEFAULT_DB_PATH}"


_DATABASE_URL = get_database_url()
_CONNECT_ARGS = {"check_same_thread": False} if _DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(_DATABASE_URL, echo=False, connect_args=_CONNECT_ARGS)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Session:
    """Create a new ORM session; the caller owns commit, rollback, and close."""

    return SessionLocal()


def create_tables() -> None:
    """Create all registered tables on the configured engine if absent."""

    Base.metadata.create_all(bind=engine)
