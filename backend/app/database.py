"""Database engine and session factory. Supports SQLite (default) and PostgreSQL."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

DB_URL = settings.DATABASE_URL
connect_args = {}
if DB_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DB_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Imports models to register them with Base.metadata."""
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
