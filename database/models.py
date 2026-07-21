"""
Database models for Security Log Analyzer.
"""

# Standard Library
from datetime import datetime
from decimal import Decimal

# SQLAlchemy
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.dialects.postgresql import JSONB

# Local Application
from database.database import Base, engine

class User(Base):
    """
    Represents an application administrator or analyst.

    This table is used to store contact information for future
    email notifications and may later support authentication.
    """

    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(
        Integer,
        Identity(),
        primary_key=True,
    )

    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        default="admin",
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

class Log(Base):
    """
    Represents a single parsed security log event.
    Each row corresponds to one event extracted from a log file.
    """

    __tablename__ = "logs"

    # Primary Key
    log_id: Mapped[int] = mapped_column(
        Integer,
        Identity(),
        primary_key=True,
    )

    # Time when the event occurred
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True,
    )

    # Log source type
    log_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # Windows channel (Security, System, Application, Sysmon, ...)
    channel: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    # Component that generated the event
    provider: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    # Original log file name
    source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Windows Event ID (nullable for Linux/Apache)
    event_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Username found inside the log
    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )
    target_username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    domain: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Network protocol (TCP, UDP, ICMP, ...)
    protocol: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    # Source IP Address
    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    # Source Port
    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Destination IP Address
    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    # Destination Port
    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Process
    image: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        index=True,
    )

    parent_image: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    command_line: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Process IDs
    process_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    parent_process_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Authentication
    logon_type: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )


    # Event status
    status: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    event_data: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Original unmodified log message
    raw_log: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Time when this event was inserted into our database
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    predictions: Mapped[list["Prediction"]] = relationship(
        back_populates="log",
        cascade="all, delete-orphan",
    )

class Prediction(Base):
    """
    Represents the analysis result of a single security log event.
    """

    __tablename__ = "predictions"

    # Primary Key
    prediction_id: Mapped[int] = mapped_column(
        Integer,
        Identity(),
        primary_key=True,
    )

    # Foreign Key -> Logs
    log_id: Mapped[int] = mapped_column(
        ForeignKey(
            "logs.log_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    # Overall prediction result
    prediction_label: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Attack family (if malicious)
    attack_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Confidence score (0.00 - 100.00)
    confidence: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
    )

    # Detection engine used
    detection_method: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    # Machine learning model name
    model_name: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    # Analysis execution time
    analysis_time_ms: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Should an alert be created?
    detected: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # Time prediction was generated
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    log: Mapped["Log"] = relationship(
        back_populates="predictions",
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="prediction",
        cascade="all, delete-orphan",
    )

class Alert(Base):
    """
    Represents a security alert generated from a prediction.
    """

    __tablename__ = "alerts"

    # Primary Key
    alert_id: Mapped[int] = mapped_column(
        Integer,
        Identity(),
        primary_key=True,
    )

    # Foreign Key -> Predictions
    prediction_id: Mapped[int] = mapped_column(
        ForeignKey(
            "predictions.prediction_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    # Alert severity
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Alert title
    title: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    # Detailed alert description
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Current alert status
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="Open",
        index=True,
    )

    # Analyst who resolved the alert
    resolved_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Resolution time
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    # Alert creation time
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # Relationship
    prediction: Mapped["Prediction"] = relationship(
        back_populates="alerts",
    )

# ---------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------

def create_tables():
    """
    Create all database tables defined in this module.
    """
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# Run this file directly to create database tables
# ---------------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("Creating database tables...")
    print("=" * 50)

    create_tables()

    print("✅ Database tables created successfully.")