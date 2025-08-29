from __future__ import annotations

"""
🧾 MoviesNow — Audit Logs (security & compliance)
=================================================

Production‑grade model to capture user‑initiated actions and key request context
for security, compliance, observability, and incident response.

Design highlights
-----------------
• **Immutable event record** keyed by UUID; timestamps are **UTC & DB‑driven**.
• Strong **query paths**: by user, by action, by request, by IP, and JSONB GIN.
• Case‑cleanliness: non‑blank checks on text fields; IP stored as **INET**.
• Relationship hygiene: `AuditLog.user` ↔ `User.audit_logs`.
• **Data retention**: `ondelete=SET NULL` on the user FK so deleting a user does
  not cascade‑delete audit history.

Conventions
-----------
• Avoid the reserved `metadata` attribute in SQLAlchemy by exposing it as
  `metadata_json` while keeping the DB column name `metadata`.
• Table name is pluralized (`audit_logs`) for consistency.
"""

from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class AuditLog(Base):
    """Immutable record of a user‑initiated action.

    Captures request correlation (`request_id`), action keyword (`action`), outcome
    (`status`), origin IP (`ip_address`), user agent, and optional structured
    metadata for audits and dashboards.

    Common queries
    --------------
    • Most recent actions per user/action: composite DESC indexes provided.
    • Request tracing: look up by `request_id` across services.
    • Anomaly sweeps: filter by `ip_address` and time window.
    """

    __tablename__ = "audit_logs"

    # ─────────────────────────────
    # 🔑 Primary Key
    # ─────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────────────────────
    # 👤 Actor
    # ─────────────────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),  # retain logs if user is deleted
        nullable=True,
        index=True,
    )

    # ─────────────────────────────
    # 📝 Action & correlation
    # ─────────────────────────────
    request_id = Column(String(128), nullable=True, index=True, doc="Correlation ID for distributed tracing")
    action = Column(String(64), nullable=False, index=True, doc="Action keyword (e.g., LOGIN, UPDATE_PROFILE)")
    status = Column(String(32), nullable=False, doc="Outcome (e.g., SUCCESS, FAILURE)")

    # ─────────────────────────────
    # 🌐 Client metadata
    # ─────────────────────────────
    ip_address = Column(INET, nullable=True, doc="IPv4/IPv6 INET type")
    user_agent = Column(String(1024), nullable=True)

    # Structured, queryable context
    metadata_json = Column("metadata", JSONB, nullable=True)

    # ─────────────────────────────
    # 🕒 Timestamps (DB‑driven UTC)
    # ─────────────────────────────
    occurred_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────────────────────
    # 🔁 Relationship
    # ─────────────────────────────
    user = relationship(
        "User",
        back_populates="audit_logs",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="AuditLog.user_id == User.id",
        foreign_keys="[AuditLog.user_id]",
    )

    # ─────────────────────────────
    # 🧭 Indexes & constraints
    # ─────────────────────────────
    __table_args__ = (
        # Non‑blank guards on key strings
        CheckConstraint("length(btrim(action)) > 0", name="ck_audit_logs_action_not_blank"),
        CheckConstraint("length(btrim(status)) > 0", name="ck_audit_logs_status_not_blank"),
        CheckConstraint(
            "(request_id IS NULL) OR (length(btrim(request_id)) > 0)",
            name="ck_audit_logs_request_id_not_blank_when_present",
        ),
        # Recent activity by user
        Index("ix_audit_logs_user_ts_desc", "user_id", text("occurred_at DESC")),
        # User + action drill‑down
        Index("ix_audit_logs_user_action_ts_desc", "user_id", "action", text("occurred_at DESC")),
        # Global action outcomes (dashboards / alerts)
        Index("ix_audit_logs_action_status_ts_desc", "action", "status", text("occurred_at DESC")),
        # Correlate by request id
        Index("ix_audit_logs_request_ts_desc", "request_id", text("occurred_at DESC")),
        # IP sweeps / anomaly checks
        Index("ix_audit_logs_ip_ts_desc", "ip_address", text("occurred_at DESC")),
        # JSONB acceleration
        Index("ix_audit_logs_metadata_gin", "metadata", postgresql_using="gin"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AuditLog id={self.id} user_id={self.user_id} action='{self.action}' "
            f"status='{self.status}' occurred_at={self.occurred_at}>"
        )
