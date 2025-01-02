"""Add modified_date and severity to BugReport

Revision ID: f662666bb76f
Revises: 6bbc2eb6eced
Create Date: 2024-11-03 18:16:43.638385

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func

# revision identifiers, used by Alembic.
revision: str = 'f662666bb76f'
down_revision: Union[str, None] = '6bbc2eb6eced'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SeverityLevel = sa.Enum('low', 'medium', 'high', name='severitylevel')

def upgrade():
    # Create the SeverityLevel enum type
    SeverityLevel.create(op.get_bind(), checkfirst=True)

    # Add new columns as nullable
    with op.batch_alter_table('bug_reports') as batch_op:
        batch_op.add_column(sa.Column('modified_date', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('severity', SeverityLevel, nullable=True))

    # Update existing rows with default values
    op.execute("UPDATE bug_reports SET modified_date = CURRENT_TIMESTAMP WHERE modified_date IS NULL;")
    op.execute("UPDATE bug_reports SET severity = 'low' WHERE severity IS NULL;")

    # Alter columns to set NOT NULL constraint
    with op.batch_alter_table('bug_reports') as batch_op:
        batch_op.alter_column('modified_date', nullable=False)
        batch_op.alter_column('severity', nullable=False)

def downgrade():
    # Drop columns and enum type
    with op.batch_alter_table('bug_reports') as batch_op:
        batch_op.drop_column('severity')
        batch_op.drop_column('modified_date')

    SeverityLevel.drop(op.get_bind(), checkfirst=True)
