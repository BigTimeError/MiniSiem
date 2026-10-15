"""add alerts

Revision ID: ad3bb3466de9
Revises: a75779df1e88
Create Date: 2026-09-24 18:12:45.508077

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'ad3bb3466de9'
down_revision: Union[str, None] = 'a75779df1e88'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing PostgreSQL enum types
    severity_enum = postgresql.ENUM(
        'info',
        'low',
        'medium',
        'high',
        'critical',
        name='severity',
        create_type=False,
    )

    alert_status_enum = postgresql.ENUM(
        'open',
        'acknowledged',
        'resolved',
        'false_positive',
        name='alert_status',
    )

    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('rule_id', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),

        sa.Column(
            'severity',
            severity_enum,
            nullable=False,
        ),

        sa.Column(
            'status',
            alert_status_enum,
            nullable=False,
        ),

        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('affected_host', sa.String(length=45), nullable=True),
        sa.Column('mitre_technique', sa.String(length=255), nullable=True),

        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'alert_events',
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.Integer(), nullable=False),

        sa.ForeignKeyConstraint(
            ['alert_id'],
            ['alerts.id'],
            ondelete='CASCADE',
        ),

        sa.ForeignKeyConstraint(
            ['event_id'],
            ['events.id'],
            ondelete='CASCADE',
        ),

        sa.PrimaryKeyConstraint('alert_id', 'event_id'),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    op.drop_table('alert_events')
    op.drop_table('alerts')
    op.execute("DROP TYPE alert_status")
