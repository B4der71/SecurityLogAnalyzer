"""
Database configuration for the Security Log Analyzer.

Responsibilities:
- Load environment variables
- Create the SQLAlchemy engine
- Create database sessions
- Provide the Base class for ORM models
- Test the PostgreSQL connection
"""

from os import getenv

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# ---------------------------------------------------------
# Load environment variables from the .env file
# ---------------------------------------------------------

load_dotenv()


# ---------------------------------------------------------
# Base class for all ORM models
# ---------------------------------------------------------

class Base(DeclarativeBase):
    """
    Every database model (User, Log, Prediction, Alert)
    will inherit from this class.
    """
    pass


# ---------------------------------------------------------
# Database Configuration
# ---------------------------------------------------------

DB_HOST = getenv("DB_HOST")
DB_PORT = getenv("DB_PORT")
DB_NAME = getenv("DB_NAME")
DB_USER = getenv("DB_USER")
DB_PASSWORD = getenv("DB_PASSWORD")


DATABASE_URL = (
    f"postgresql+psycopg2://"
    f"{DB_USER}:{DB_PASSWORD}@"
    f"{DB_HOST}:{DB_PORT}/"
    f"{DB_NAME}"
)


# ---------------------------------------------------------
# SQLAlchemy Engine
# ---------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    echo=False,
)


# ---------------------------------------------------------
# Session Factory
# ---------------------------------------------------------

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


# ---------------------------------------------------------
# Database Connection Test
# ---------------------------------------------------------

def test_connection() -> bool:
    """
    Tests whether PostgreSQL is reachable.

    Returns:
        bool:
            True if successful.
            False otherwise.
    """

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        print("✅ Successfully connected to PostgreSQL.")
        return True

    except Exception as error:
        print("❌ Failed to connect to PostgreSQL.")
        print(error)
        return False


# ---------------------------------------------------------
# Run this file directly to test the connection
# ---------------------------------------------------------

if __name__ == "__main__":
    test_connection()