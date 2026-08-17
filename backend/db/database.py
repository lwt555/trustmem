"""SQLAlchemy engine and session factory."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session as SASession

DATABASE_URL = "sqlite:///trustmem.db"

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, future=True)


def get_db() -> SASession:
    return SessionLocal()


def init_db() -> None:
    from backend.db.models import Base
    Base.metadata.create_all(bind=engine)
    _ensure_columns()


def _ensure_columns() -> None:
    """轻量幂等迁移：为既有 SQLite 库补齐后加列（create_all 不会 ALTER 已有表）。"""
    from sqlalchemy import text
    with engine.begin() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(memory_chunks)"))}
        if "derived_from_consult" not in cols:
            conn.execute(text(
                "ALTER TABLE memory_chunks ADD COLUMN derived_from_consult BOOLEAN "
                "DEFAULT 0 NOT NULL"))
