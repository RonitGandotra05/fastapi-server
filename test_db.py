from database import SessionLocal
from models import User, BugReport

def test_db():
    db = SessionLocal()
    try:
        # Test query
        users = db.query(User).all()
        bugs = db.query(BugReport).all()
        print(f"✅ Database working! Found {len(users)} users and {len(bugs)} bug reports")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    test_db()
