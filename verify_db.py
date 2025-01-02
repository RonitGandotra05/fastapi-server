from sqlalchemy import inspect, MetaData
from database import engine
from models import Base
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def verify_database_structure():
    # Get database inspector
    inspector = inspect(engine)
    
    # Get all tables from database
    db_tables = inspector.get_table_names()
    logger.info(f"Database tables: {db_tables}")
    
    # Get all tables from models
    model_tables = Base.metadata.tables
    logger.info(f"Model tables: {list(model_tables.keys())}")
    
    # Compare tables
    for table_name in model_tables:
        if table_name not in db_tables:
            logger.error(f"❌ Table {table_name} exists in models but not in database")
            continue
            
        # Get columns from database
        db_columns = {col['name']: col for col in inspector.get_columns(table_name)}
        
        # Get columns from model
        model_columns = {col.name: col for col in model_tables[table_name].columns}
        
        # Compare columns
        for col_name, model_col in model_columns.items():
            if col_name not in db_columns:
                logger.error(f"❌ Column {col_name} in table {table_name} exists in model but not in database")
                continue
                
            logger.info(f"✅ Column {col_name} in table {table_name} exists in both model and database")

    logger.info("Database verification complete")

if __name__ == "__main__":
    verify_database_structure() 