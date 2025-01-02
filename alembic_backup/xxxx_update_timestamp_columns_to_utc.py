"""update_timestamp_columns_to_utc

Revision ID: xxxx
Revises: e603b56c19f0
Create Date: 2023-12-22
"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone

# revision identifiers
revision = 'xxxx'
down_revision = 'e603b56c19f0'
branch_labels = None
depends_on = None

def upgrade():
    # SQLite doesn't support ALTER COLUMN, so we need to:
    # 1. Create new tables with the desired schema
    # 2. Copy data
    # 3. Drop old tables
    # 4. Rename new tables

    # For bug_reports
    with op.batch_alter_table('bug_reports') as batch_op:
        batch_op.alter_column('modified_date',
            type_=sa.DateTime(timezone=True),
            existing_type=sa.DateTime(),
            existing_nullable=False)

    # For bug_report_comments
    with op.batch_alter_table('bug_report_comments') as batch_op:
        batch_op.alter_column('created_at',
            type_=sa.DateTime(timezone=True),
            existing_type=sa.DateTime(),
            existing_nullable=False)

def downgrade():
    # For bug_reports
    with op.batch_alter_table('bug_reports') as batch_op:
        batch_op.alter_column('modified_date',
            type_=sa.DateTime(),
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=False)

    # For bug_report_comments
    with op.batch_alter_table('bug_report_comments') as batch_op:
        batch_op.alter_column('created_at',
            type_=sa.DateTime(),
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=False) 