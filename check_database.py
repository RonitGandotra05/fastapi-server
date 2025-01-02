from sqlalchemy import inspect, MetaData, text
from database import engine, Base
from models import User, BugReport, Project, BugReportComment, BugReportCC
import logging
from typing import Dict, List, Set
import sqlite3
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_sqlite_path() -> str:
    """Extract SQLite database path from DATABASE_URL."""
    from database import DATABASE_URL
    return DATABASE_URL.replace('sqlite:///', '')

def get_sqlite_info() -> Dict:
    """Get SQLite table and index information directly using sqlite3."""
    db_path = get_sqlite_path()
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return {}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    result = {}
    for table in tables:
        # Get table schema
        cursor.execute(f"PRAGMA table_info({table})")
        columns = {row[1]: {
            'type': row[2],
            'nullable': not row[3],
            'primary_key': row[5]
        } for row in cursor.fetchall()}
        
        # Get indexes
        cursor.execute(f"PRAGMA index_list({table})")
        indexes = []
        for idx in cursor.fetchall():
            index_name = idx[1]
            cursor.execute(f"PRAGMA index_info({index_name})")
            index_columns = [row[2] for row in cursor.fetchall()]
            indexes.append({
                'name': index_name,
                'columns': index_columns,
                'unique': idx[2]
            })
        
        result[table] = {
            'columns': columns,
            'indexes': indexes
        }
    
    conn.close()
    return result

def get_model_info() -> Dict:
    """Get table and index information from SQLAlchemy models."""
    inspector = inspect(engine)
    metadata = Base.metadata
    
    result = {}
    for table_name, table in metadata.tables.items():
        # Get columns
        columns = {col.name: {
            'type': str(col.type),
            'nullable': col.nullable,
            'primary_key': col.primary_key
        } for col in table.columns}
        
        # Get indexes
        indexes = []
        for idx in table.indexes:
            indexes.append({
                'name': idx.name,
                'columns': [col.name for col in idx.columns],
                'unique': idx.unique
            })
        
        result[table_name] = {
            'columns': columns,
            'indexes': indexes
        }
    
    return result

def compare_database_with_models():
    """Compare database structure with models."""
    db_info = get_sqlite_info()
    model_info = get_model_info()
    
    logger.info("=== Database Structure Analysis ===")
    
    # Compare tables
    db_tables = set(db_info.keys())
    model_tables = set(model_info.keys())
    
    logger.info("\n=== Tables ===")
    logger.info(f"Database tables: {sorted(db_tables)}")
    logger.info(f"Model tables: {sorted(model_tables)}")
    
    if missing_tables := model_tables - db_tables:
        logger.error(f"❌ Tables in models but not in database: {missing_tables}")
    if extra_tables := db_tables - model_tables:
        logger.warning(f"⚠️ Tables in database but not in models: {extra_tables}")
    
    # Compare structure for each table
    logger.info("\n=== Table Structure ===")
    for table in model_tables & db_tables:
        logger.info(f"\nChecking table: {table}")
        
        db_table = db_info[table]
        model_table = model_info[table]
        
        # Compare columns
        db_cols = set(db_table['columns'].keys())
        model_cols = set(model_table['columns'].keys())
        
        if missing_cols := model_cols - db_cols:
            logger.error(f"❌ Columns in model but not in database: {missing_cols}")
        if extra_cols := db_cols - model_cols:
            logger.warning(f"⚠️ Columns in database but not in model: {extra_cols}")
            
        # Compare indexes
        db_indexes = {(idx['name'], tuple(sorted(idx['columns'])), idx['unique']) 
                     for idx in db_table['indexes']}
        model_indexes = {(idx['name'], tuple(sorted(idx['columns'])), idx['unique']) 
                        for idx in model_table['indexes']}
        
        if missing_indexes := model_indexes - db_indexes:
            logger.error(f"❌ Indexes in model but not in database: {missing_indexes}")
        if extra_indexes := db_indexes - model_indexes:
            logger.warning(f"⚠️ Indexes in database but not in model: {extra_indexes}")
        
        # Check column properties
        for col in model_cols & db_cols:
            db_col = db_table['columns'][col]
            model_col = model_table['columns'][col]
            
            if db_col['nullable'] != model_col['nullable']:
                logger.error(
                    f"❌ Nullable mismatch for {table}.{col}: "
                    f"DB={db_col['nullable']}, Model={model_col['nullable']}"
                )
            if db_col['primary_key'] != model_col['primary_key']:
                logger.error(
                    f"❌ Primary key mismatch for {table}.{col}: "
                    f"DB={db_col['primary_key']}, Model={model_col['primary_key']}"
                )

if __name__ == "__main__":
    logger.info("Starting database structure verification...")
    compare_database_with_models()
    logger.info("\nVerification complete!") 