from sqlalchemy import inspect, MetaData, text
from database import engine, Base
import logging
from typing import Dict, List
import sqlite3
from database import DATABASE_URL

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_path():
    return DATABASE_URL.replace('sqlite:///', '')

def verify_database_structure():
    """Verify database structure and list all tables and indexes."""
    inspector = inspect(engine)
    
    # Get all tables from database
    db_tables = inspector.get_table_names()
    
    # Get all tables from models
    model_tables = set(Base.metadata.tables.keys())
    
    logger.info("=== Database Tables and Indexes Analysis ===\n")
    
    # Connect to SQLite directly for detailed index information
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()
    
    for table in sorted(db_tables):
        logger.info(f"\n📋 Table: {table}")
        
        # Get columns
        columns = inspector.get_columns(table)
        logger.info("\nColumns:")
        for col in columns:
            nullable = "NULL" if col['nullable'] else "NOT NULL"
            pk = "PRIMARY KEY" if col.get('primary_key', False) else ""
            logger.info(f"  ├─ {col['name']}: {col['type']} {nullable} {pk}")
        
        # Get indexes using SQLite PRAGMA
        cursor.execute(f"PRAGMA index_list('{table}')")
        indexes = cursor.fetchall()
        
        if indexes:
            logger.info("\nIndexes:")
            for idx in indexes:
                index_name = idx[1]
                is_unique = "UNIQUE" if idx[2] else ""
                
                # Get columns in this index
                cursor.execute(f"PRAGMA index_info('{index_name}')")
                index_columns = cursor.fetchall()
                columns = [col[2] for col in index_columns]
                
                logger.info(f"  ├─ {index_name} ({is_unique})")
                logger.info(f"  │  └─ Columns: {', '.join(columns)}")
        
        # Get foreign keys
        cursor.execute(f"PRAGMA foreign_key_list('{table}')")
        foreign_keys = cursor.fetchall()
        
        if foreign_keys:
            logger.info("\nForeign Keys:")
            for fk in foreign_keys:
                from_col = fk[3]
                to_table = fk[2]
                to_col = fk[4]
                on_delete = fk[5]
                logger.info(f"  ├─ {from_col} -> {to_table}({to_col})")
                logger.info(f"  │  └─ ON DELETE: {on_delete}")
    
    conn.close()
    
    # Compare with models
    logger.info("\n=== Model Verification ===")
    logger.info(f"Tables in database: {sorted(db_tables)}")
    logger.info(f"Tables in models: {sorted(model_tables)}")
    
    if missing_tables := model_tables - set(db_tables):
        logger.error(f"❌ Tables in models but missing in database: {missing_tables}")
    if extra_tables := set(db_tables) - model_tables - {'alembic_version'}:
        logger.warning(f"⚠️ Extra tables in database: {extra_tables}")

def verify_data_consistency():
    """Verify basic data consistency in tables."""
    with engine.connect() as conn:
        # Get row counts for each table
        logger.info("\n=== Table Statistics ===")
        for table in inspector.get_table_names():
            result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = result.scalar()
            logger.info(f"📊 {table}: {count} rows")

if __name__ == "__main__":
    inspector = inspect(engine)
    verify_database_structure()
    verify_data_consistency()
    logger.info("\nDatabase verification complete!") 