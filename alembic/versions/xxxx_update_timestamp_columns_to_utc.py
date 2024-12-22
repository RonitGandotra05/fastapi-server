"""update_timestamp_columns_to_utc

Revision ID: xxxx
Revises: e603b56c19f0
Create Date: 2023-12-22
"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone

# revision identifiers
revision = 'xxxx'  # Alembic will generate this
down_revision = 'e603b56c19f0'  # Your previous migration
branch_labels = None
depends_on = None

def upgrade():
    # Update existing timestamps to UTC
    op.execute("""
        ALTER TABLE bug_reports 
        ALTER COLUMN modified_date TYPE TIMESTAMP WITH TIME ZONE 
        USING modified_date AT TIME ZONE 'UTC'
    """)

    op.execute("""
        ALTER TABLE bug_report_comments 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE 
        USING created_at AT TIME ZONE 'UTC'
    """)

    # Set default to UTC timestamp for new records
    op.alter_column('bug_reports', 'modified_date',
        type_=sa.DateTime(timezone=True),
        server_default=sa.text('NOW()'),
        existing_nullable=True)

    op.alter_column('bug_report_comments', 'created_at',
        type_=sa.DateTime(timezone=True),
        server_default=sa.text('NOW()'),
        existing_nullable=True)

def downgrade():
    # Convert back to timestamp without timezone
    op.execute("""
        ALTER TABLE bug_reports 
        ALTER COLUMN modified_date TYPE TIMESTAMP 
        USING modified_date AT TIME ZONE 'UTC'
    """)

    op.execute("""
        ALTER TABLE bug_report_comments 
        ALTER COLUMN created_at TYPE TIMESTAMP 
        USING created_at AT TIME ZONE 'UTC'
    """)

    op.alter_column('bug_reports', 'modified_date',
        type_=sa.DateTime(timezone=False),
        server_default=sa.text('NOW()'),
        existing_nullable=True)

    op.alter_column('bug_report_comments', 'created_at',
        type_=sa.DateTime(timezone=False),
        server_default=sa.text('NOW()'),
        existing_nullable=True) 