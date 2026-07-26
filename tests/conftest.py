import pytest

from database.database import SessionLocal


@pytest.fixture
def db_session():
    session = SessionLocal()

    try:
        yield session
    finally:
        session.rollback()
        session.close()