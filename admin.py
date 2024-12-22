# create_admin_user.py
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./bug_reports.db')
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)

Base.metadata.create_all(bind=engine)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_admin_user(name: str, email: str, phone: str, password: str):
    db = SessionLocal()
    try:
        admin = User(
            name=name,
            email=email,
            phone=phone,
            password_hash=get_password_hash(password),
            is_admin=True
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        print("Admin user created successfully.")
    except Exception as e:
        db.rollback()
        print(f"Error creating admin user: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    print("=== Admin User Creation ===")
    name = input("Enter admin name: ").strip()
    email = input("Enter admin email: ").strip()
    phone = input("Enter admin phone: ").strip()
    password = input("Enter admin password: ").strip()
    create_admin_user(name, email, phone, password)
