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
