"""finding_lifecycle

Adds triage state to ``findings``: ``status`` (open / acknowledged /
resolved / false_positive), ``note`` (free-text analyst comment), and
``resolved_at`` (stamped when the status leaves the active set).

Revision ID: 2bee097a804e
Revises: 31a5b85df782
Create Date: 2026-04-22 18:23:32.295397

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2bee097a804e"
down_revision: str | None = "31a5b85df782"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Batch mode for SQLite compatibility - Postgres will just run the ALTERs.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "status",
                sa.String(length=32),
                nullable=False,
                server_default="open",
            )
        )
        batch_op.add_column(
            sa.Column("note", sa.Text(), nullable=False, server_default="")
        )
        batch_op.add_column(
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("resolved_at")
        batch_op.drop_column("note")
        batch_op.drop_column("status")
