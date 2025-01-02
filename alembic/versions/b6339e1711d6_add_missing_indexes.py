"""add_missing_indexes

Revision ID: b6339e1711d6
Revises: d32a25bb578d
Create Date: <timestamp>

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

# revision identifiers, used by Alembic.
revision = 'b6339e1711d6'
down_revision = 'd32a25bb578d'
branch_labels = None
depends_on = None

def cleanup_temp_tables(conn):
    temp_tables = [
        '_alembic_tmp_bug_report_comments',
        '_alembic_tmp_bug_reports'
    ]
    for table in temp_tables:
        conn.execute(text(f"DROP TABLE IF EXISTS {table}"))

def has_index(table_name, index_name):
    conn = op.get_bind()
    inspector = inspect(conn)
    indexes = inspector.get_indexes(table_name)
    return any(idx['name'] == index_name for idx in indexes)

def upgrade() -> None:
    # Clean up any leftover temporary tables first
    conn = op.get_bind()
    cleanup_temp_tables(conn)
    
    # Now proceed with the migrations
    with op.batch_alter_table('bug_report_comments', recreate='always') as batch_op:
        batch_op.alter_column('bug_report_id',
                            existing_type=sa.Integer(),
                            nullable=False)
        batch_op.alter_column('created_at',
                            existing_type=sa.DateTime(timezone=True),
                            nullable=True)
        if not has_index('bug_report_comments', 'ix_bug_report_comments_id'):
            batch_op.create_index('ix_bug_report_comments_id', ['id'], unique=False)

    with op.batch_alter_table('bug_reports', recreate='always') as batch_op:
        batch_op.alter_column('image_url',
                            existing_type=sa.String(),
                            nullable=True)
        batch_op.alter_column('media_type',
                            existing_type=sa.String(),
                            nullable=True)
        batch_op.alter_column('modified_date',
                            existing_type=sa.DateTime(),
                            nullable=True)
        if not has_index('bug_reports', 'ix_bug_reports_id'):
            batch_op.create_index('ix_bug_reports_id', ['id'], unique=False)

def downgrade() -> None:
    # Clean up any leftover temporary tables first
    conn = op.get_bind()
    cleanup_temp_tables(conn)
    
    with op.batch_alter_table('bug_report_comments') as batch_op:
        if has_index('bug_report_comments', 'ix_bug_report_comments_id'):
            batch_op.drop_index('ix_bug_report_comments_id')

    with op.batch_alter_table('bug_reports') as batch_op:
        if has_index('bug_reports', 'ix_bug_reports_id'):
            batch_op.drop_index('ix_bug_reports_id')
