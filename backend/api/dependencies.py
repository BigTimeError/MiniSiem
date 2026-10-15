from collections.abc import Generator

from sqlalchemy.orm import Session

from backend.database.database import SessionLocal


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()