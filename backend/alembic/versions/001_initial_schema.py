"""Initial AETHER schema

Revision ID: 001_initial
Revises:
Create Date: 2026-06-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("threat_level", sa.Text, nullable=False, server_default="unknown"),
        sa.Column("initial_plan", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("thought_trace", JSONB, nullable=True),
        sa.Column("results", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("final_report", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("remediations", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("scans_id_idx", "scans", ["id"], unique=True)

    op.create_table(
        "consent_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
        sa.Column("ip_address", sa.Text, nullable=True),
    )

    op.create_table(
        "scan_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", UUID(as_uuid=True), nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("threat_level", sa.Text, nullable=True),
        sa.Column("scan_started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
        sa.Column("scan_completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("scan_sessions_scan_id_idx", "scan_sessions", ["scan_id"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", UUID(as_uuid=True), nullable=True),
        sa.Column("attack_vector", sa.Text, nullable=True),
        sa.Column("detected_threat", sa.Text, nullable=True),
        sa.Column("evidence_snippet", sa.Text, nullable=True),
        sa.Column("provided_solution", sa.Text, nullable=True),
        sa.Column("is_fixed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("category", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("detail", sa.Text, nullable=False),
        sa.Column("evidence", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
    )
    op.create_index("vulnerabilities_scan_id_idx", "vulnerabilities", ["scan_id"])

    op.create_table(
        "profiles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("email", sa.Text, nullable=True),
        sa.Column("profile_type", sa.Text, nullable=False),
        sa.Column("label", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'\"{}\"'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
    )
    op.create_index("profiles_scan_id_idx", "profiles", ["scan_id"])

    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.Text, unique=True, nullable=False),
        sa.Column("name", sa.Text, nullable=True),
        sa.Column("provider", sa.Text, nullable=False, server_default="email"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("users_email_idx", "users", ["email"])

    op.create_table(
        "magic_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("token", sa.Text, unique=True, nullable=False),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
    )
    op.create_index("magic_links_token_idx", "magic_links", ["token"])

    op.create_table(
        "revoked_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("token_jti", sa.Text, unique=True, nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("revoked_tokens_jti_idx", "revoked_tokens", ["token_jti"])
    op.create_index("revoked_tokens_user_idx", "revoked_tokens", ["user_id"])

    op.create_table(
        "remediation_history",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("vuln_id", sa.Text, nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("language", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("timezone('utc', now())")),
    )
    op.create_index("remediation_history_scan_idx", "remediation_history", ["scan_id"])


def downgrade() -> None:
    op.drop_table("remediation_history")
    op.drop_table("revoked_tokens")
    op.drop_table("magic_links")
    op.drop_table("users")
    op.drop_table("profiles")
    op.drop_table("vulnerabilities")
    op.drop_table("scan_sessions")
    op.drop_table("consent_logs")
    op.drop_table("scans")
