"""Add Project model and project_id to BugReport

Revision ID: 987e64cd068e
Revises: f662666bb76f
Create Date: 2024-11-05 17:54:09.951387

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '987e64cd068e'
down_revision: Union[str, None] = 'f662666bb76f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Create 'projects' table
    op.create_table(
        'projects',
        sa.Column('id', sa.Integer(), primary_key=True, index=True, nullable=False),
        sa.Column('name', sa.String(), unique=True, nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now())
    )

    # Use batch operations to alter 'bug_reports' table
    with op.batch_alter_table('bug_reports', schema=None) as batch_op:
        batch_op.add_column(sa.Column('project_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_bug_reports_project_id_projects',
            'projects',
            ['project_id'], ['id'],
            ondelete='SET NULL'
        )
        batch_op.create_index('ix_bug_reports_project_id', ['project_id'])


def downgrade():
    # Use batch operations to revert changes to 'bug_reports' table
    with op.batch_alter_table('bug_reports', schema=None) as batch_op:
        batch_op.drop_index('ix_bug_reports_project_id')
        batch_op.drop_constraint('fk_bug_reports_project_id_projects', type_='foreignkey')
        batch_op.drop_column('project_id')

    # Drop 'projects' table
    op.drop_table('projects')
