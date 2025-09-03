"""
Media model enhancements + Bundle table.

- Add technical columns to media_assets (codecs/container/hdr/stereo/bitrate/label/lifecycle).
- Create bundles table for season ZIPs.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision = "20250903_01_media_and_bundles"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- New enum types for assets ---
    asset_container = sa.Enum("MKV", "MP4", "TS", name="asset_container")
    asset_container.create(op.get_bind(), checkfirst=True)

    stereoscopic_mode = sa.Enum("MONO", "SBS", "TB", name="stereoscopic_mode")
    stereoscopic_mode.create(op.get_bind(), checkfirst=True)

    lifecycle_class = sa.Enum("HOT", "WARM", "ARCHIVE", name="lifecycle_class")
    lifecycle_class.create(op.get_bind(), checkfirst=True)

    # Existing enums (do not recreate types)
    video_codec = sa.Enum("H264", "H265", "VP9", "AV1", "NONE", name="video_codec", create_type=False)
    audio_codec = sa.Enum("AAC", "AC3", "EAC3", "OPUS", "NONE", name="audio_codec", create_type=False)
    hdr_format = sa.Enum("SDR", "HDR10", "HLG", "DOLBY_VISION", name="hdr_format", create_type=False)

    # --- Extend media_assets ---
    op.add_column("media_assets", sa.Column("video_codec", video_codec, nullable=True))
    op.add_column("media_assets", sa.Column("audio_codec", audio_codec, nullable=True))
    op.add_column("media_assets", sa.Column("container", asset_container, nullable=True))
    op.add_column("media_assets", sa.Column("hdr", hdr_format, nullable=True))
    op.add_column("media_assets", sa.Column("stereoscopic", stereoscopic_mode, nullable=True))
    op.add_column("media_assets", sa.Column("channels", sa.String(length=8), nullable=True))
    op.add_column("media_assets", sa.Column("bitrate_bps", sa.Integer(), nullable=True))
    op.add_column("media_assets", sa.Column("label", sa.String(length=128), nullable=True))
    op.add_column("media_assets", sa.Column("lifecycle_class", lifecycle_class, nullable=False, server_default=sa.text("'HOT'")))

    # Indexes for new columns
    op.create_index("ix_media_assets_codecs", "media_assets", ["video_codec", "audio_codec"], unique=False)
    op.create_index("ix_media_assets_container", "media_assets", ["container"], unique=False)
    op.create_check_constraint("ck_media_assets_bitrate_nonneg", "media_assets", "(bitrate_bps IS NULL) OR (bitrate_bps >= 0)")
    op.create_check_constraint("ck_media_assets_label_not_blank", "media_assets", "(label IS NULL) OR (length(btrim(label)) > 0)")

    # --- Create bundles table ---
    op.create_table(
        "bundles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("title_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("titles.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("season_number", sa.Integer(), nullable=True, index=True),
        sa.Column("episode_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_bundles_storage_key"),
    )
    # Bundle indexes & constraints
    op.create_index("ix_bundles_title_id", "bundles", ["title_id"], unique=False)
    op.create_index("ix_bundles_season_number", "bundles", ["season_number"], unique=False)
    op.create_index("ix_bundles_expires_at", "bundles", ["expires_at"], unique=False)
    op.create_index("ix_bundles_created_at", "bundles", ["created_at"], unique=False)
    op.create_check_constraint("ck_bundle_storage_key_not_blank", "bundles", "length(btrim(storage_key)) > 0")
    op.create_check_constraint("ck_bundle_size_nonneg", "bundles", "(size_bytes IS NULL) OR (size_bytes >= 0)")
    op.create_check_constraint("ck_bundle_label_not_blank", "bundles", "(label IS NULL) OR (length(btrim(label)) > 0)")
    op.create_check_constraint("ck_bundle_season_nonneg", "bundles", "(season_number IS NULL) OR (season_number >= 0)")
    op.create_check_constraint("ck_bundle_expiry_after_create", "bundles", "(expires_at IS NULL) OR (expires_at > created_at)")

    # Partial unique (Postgres) for (title_id, season_number) when season specified
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_bundle_per_title_season
        ON bundles (title_id, season_number)
        WHERE season_number IS NOT NULL;
        """
    )


def downgrade() -> None:
    # Drop bundles first
    op.drop_index("uq_bundle_per_title_season", table_name=None, postgresql_where=None)  # safe if exists
    op.drop_table("bundles")

    # Remove media_assets additions
    op.drop_constraint("ck_media_assets_bitrate_nonneg", "media_assets", type_="check")
    op.drop_constraint("ck_media_assets_label_not_blank", "media_assets", type_="check")
    op.drop_index("ix_media_assets_codecs", table_name="media_assets")
    op.drop_index("ix_media_assets_container", table_name="media_assets")

    op.drop_column("media_assets", "lifecycle_class")
    op.drop_column("media_assets", "label")
    op.drop_column("media_assets", "bitrate_bps")
    op.drop_column("media_assets", "channels")
    op.drop_column("media_assets", "stereoscopic")
    op.drop_column("media_assets", "hdr")
    op.drop_column("media_assets", "container")
    op.drop_column("media_assets", "audio_codec")
    op.drop_column("media_assets", "video_codec")

    # Drop new enum types
    lifecycle_class = sa.Enum(name="lifecycle_class")
    stereoscopic_mode = sa.Enum(name="stereoscopic_mode")
    asset_container = sa.Enum(name="asset_container")
    lifecycle_class.drop(op.get_bind(), checkfirst=True)
    stereoscopic_mode.drop(op.get_bind(), checkfirst=True)
    asset_container.drop(op.get_bind(), checkfirst=True)
    # Extend media_asset_kind with additional values (idempotent)
    for val in ("original", "download", "hls", "artwork", "bundle"):
        op.execute(f"ALTER TYPE media_asset_kind ADD VALUE IF NOT EXISTS '{val}'")

