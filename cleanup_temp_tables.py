from sqlalchemy import text
from database import engine

def cleanup_temp_tables():
    with engine.connect() as conn:
        # Drop temporary tables if they exist
        temp_tables = [
            '_alembic_tmp_bug_report_comments',
            '_alembic_tmp_bug_reports',
            '_alembic_tmp_bug_report_cc'
        ]
        
        for table in temp_tables:
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
                print(f"✅ Cleaned up {table}")
            except Exception as e:
                print(f"❌ Error cleaning up {table}: {e}")
        
        conn.commit()
        print("Cleanup complete!")

if __name__ == "__main__":
    cleanup_temp_tables() 