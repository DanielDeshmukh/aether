"""Add git target columns to targets table

Revision ID: 002_git_targets
Revises: 001_initial
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa

revision = "002_git_targets"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("git_provider", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("access_token", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("repository", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("project_id", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("default_branch", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("base_branch", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("api_base_url", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("repo_web_url", sa.Text, nullable=True))
    op.add_column("targets", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "updated_at")
    op.drop_column("targets", "repo_web_url")
    op.drop_column("targets", "api_base_url")
    op.drop_column("targets", "base_branch")
    op.drop_column("targets", "default_branch")
    op.drop_column("targets", "project_id")
    op.drop_column("targets", "repository")
    op.drop_column("targets", "access_token")
    op.drop_column("targets", "git_provider")
