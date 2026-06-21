"""Initial migration: create control_chunks, scans, and findings tables.

Revision ID: 001
Revises:
Create Date: 2026-06-22
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "control_chunks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("framework", sa.String(50), nullable=False),
        sa.Column("control_id", sa.String(20), nullable=False),
        sa.Column("family", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("embedding", sa.LargeBinary(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_control_chunks_framework", "control_chunks", ["framework"]
    )
    op.create_index(
        "ix_control_chunks_control_id", "control_chunks", ["control_id"]
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.String(64), nullable=False),
        sa.Column("target_path", sa.String(1024), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("summary_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(64), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("engine", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("resource", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("raw_description", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("compliance_json", sa.Text(), nullable=True),
        sa.Column("priority_score", sa.Integer(), nullable=True),
        sa.Column("priority_rationale", sa.Text(), nullable=True),
        sa.Column("patch_diff", sa.Text(), nullable=True),
        sa.Column("validated", sa.Boolean(), nullable=True),
        sa.Column("validation_log", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_findings_scan_id", "findings", ["scan_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_index("ix_control_chunks_control_id", table_name="control_chunks")
    op.drop_index("ix_control_chunks_framework", table_name="control_chunks")
    op.drop_table("control_chunks")
