# app/db/models/audit_log.py

"""
Defines the AuditLog model to track user actions and request metadata
for security, compliance, and traceability.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class AuditLog(Base):
    """
    Represents a record of a user-initiated action.

    Captures key request details such as action, result status, client info,
    and optional trace metadata for auditing and monitoring.
    """

    __tablename__ = "audit_log"

    # ─────────────────────────────
    # 🔑 Primary Key
    # ─────────────────────────────
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        index=True,  # kept as-is (even though PK is already indexed) to avoid field changes
        comment="Primary UUID key for the audit log entry",
    )

    # ─────────────────────────────
    # 👤 Actor Info
    # ─────────────────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="ID of the user who performed the action",
    )

    # ─────────────────────────────
    # 📝 Action Details
    # ─────────────────────────────
    request_id = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Correlation ID for tracing across services/logs",
    )

    action = Column(
        String(64),
        nullable=False,
        index=True,
        comment="Short keyword for the action (e.g. LOGIN, LOGOUT, UPDATE_PROFILE)",
    )

    status = Column(
        String(64),
        nullable=False,
        comment="Outcome status of the action (e.g. SUCCESS, FAILURE)",
    )

    # ─────────────────────────────
    # 🌐 Client Metadata
    # ─────────────────────────────
    ip_address = Column(
        String(45),
        nullable=True,
        comment="IPv4 or IPv6 address of the request origin",
    )

    user_agent = Column(
        String(512),
        nullable=True,
        comment="User agent string of the client's browser or device",
    )

    meta_data = Column(
        JSONB,
        nullable=True,
        comment="Optional structured metadata (stored as JSONB for fast querying)",
    )

    # ─────────────────────────────
    # 🕒 Timestamps
    # ─────────────────────────────
    # Migrate from Python default(datetime.utcnow) to a DB-side UTC default to avoid tz drift.
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        comment="UTC timestamp when the action occurred",
    )

    # ─────────────────────────────
    # 🔁 Relationships
    # ─────────────────────────────
    user = relationship(
        "User",
        back_populates="audit_logs",
        lazy="selectin",
        passive_deletes=True,
    )

    # ─────────────────────────────
    # 🧭 Indexes (composite / covering) & JSONB GIN
    # ─────────────────────────────
    __table_args__ = (
        # Recent activity for a user
        Index("ix_audit_log_user_ts_desc", "user_id", text("timestamp DESC")),
        # User + action drill-down
        Index("ix_audit_log_user_action_ts_desc", "user_id", "action", text("timestamp DESC")),
        # Global action outcomes (dashboards / alerts)
        Index("ix_audit_log_action_status_ts_desc", "action", "status", text("timestamp DESC")),
        # Correlate by request id
        Index("ix_audit_log_request_ts_desc", "request_id", text("timestamp DESC")),
        # IP sweeps / anomaly checks
        Index("ix_audit_log_ip_ts_desc", "ip_address", text("timestamp DESC")),
        # JSONB acceleration
        Index("ix_audit_log_meta_data_gin", "meta_data", postgresql_using="gin"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuditLog id={self.id} user_id={self.user_id} "
            f"action='{self.action}' status='{self.status}' timestamp={self.timestamp}>"
        )
