"""trim user names

Revision ID: 2024_01_trim_users
Revises: 508a9ee4a517
Create Date: 2024-01-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = '2024_01_trim_users'
down_revision = '508a9ee4a517'  # Updated to use the existing head
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Get bind for raw SQL execution
    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        # First, update the users table
        session.execute(
            text("""
            UPDATE users 
            SET name = TRIM(name) 
            WHERE name != TRIM(name)
            """)
        )

        # Then, update the bug_report_comments table to match the trimmed user names
        session.execute(
            text("""
            UPDATE bug_report_comments 
            SET user_name = TRIM(user_name) 
            WHERE user_name != TRIM(user_name)
            """)
        )

        session.commit()

    except Exception as e:
        session.rollback()
        raise e

    finally:
        session.close()

def downgrade() -> None:
    # Cannot meaningfully downgrade this migration as we don't store the original whitespace
    pass 