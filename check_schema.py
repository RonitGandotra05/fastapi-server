# save as check_schema_detailed.py
from sqlalchemy import inspect, text
from models import Base, User, BugReport, Project, BugReportCC, BugReportComment
from database import engine
import sqlalchemy as sa

def get_column_type_string(column):
    """Convert SQLAlchemy column type to string representation"""
    if isinstance(column.type, sa.String):
        return f"VARCHAR({column.type.length if column.type.length else ''})"
    elif isinstance(column.type, sa.Integer):
        return "INTEGER"
    elif isinstance(column.type, sa.Boolean):
        return "BOOLEAN"
    elif isinstance(column.type, sa.Text):
        return "TEXT"
    elif isinstance(column.type, sa.DateTime):
        return "DATETIME"
    elif isinstance(column.type, sa.Enum):
        return f"VARCHAR"  # SQLite stores ENUMs as VARCHAR
    return str(column.type)

def check_tables_detailed():
    inspector = inspect(engine)
    
    print("\n=== Detailed Schema Analysis ===\n")
    
    # Get all tables from models
    model_tables = Base.metadata.tables
    # Get all tables from database
    db_tables = inspector.get_table_names()
    
    for table_name, table in model_tables.items():
        print(f"\nChecking table: {table_name}")
        print("-" * 50)
        
        if table_name not in db_tables:
            print(f"❌ Table missing in database: {table_name}")
            continue
            
        # Get columns from model
        model_columns = {c.name: c for c in table.columns}
        # Get columns from database
        db_columns = {c['name']: c for c in inspector.get_columns(table_name)}
        
        print("\nColumn Analysis:")
        print("{:<20} {:<15} {:<10} {:<10} {:<15}".format(
            "Column Name", "Type", "Nullable", "PK", "Default"
        ))
        print("-" * 70)
        
        # Check each model column
        for col_name, model_col in model_columns.items():
            if col_name not in db_columns:
                print(f"❌ Missing column in DB: {col_name}")
                continue
                
            db_col = db_columns[col_name]
            
            # Compare specifications
            model_type = get_column_type_string(model_col)
            db_type = db_col['type'].__class__.__name__
            
            is_match = True
            mismatch_details = []
            
            # Check type
            if model_type.upper() != str(db_type).upper():
                is_match = False
                mismatch_details.append(f"Type mismatch: Model={model_type}, DB={db_type}")
            
            # Check nullable
            if model_col.nullable != db_col['nullable']:
                is_match = False
                mismatch_details.append(f"Nullable mismatch: Model={model_col.nullable}, DB={db_col['nullable']}")
            
            # Check primary key
            if model_col.primary_key != db_col['primary_key']:
                is_match = False
                mismatch_details.append(f"PK mismatch: Model={model_col.primary_key}, DB={db_col['primary_key']}")
            
            print("{:<20} {:<15} {:<10} {:<10} {:<15}".format(
                col_name,
                str(db_type),
                str(db_col['nullable']),
                str(db_col['primary_key']),
                str(db_col.get('default', 'None'))
            ))
            
            if not is_match:
                print("   ⚠️ Mismatches found:")
                for detail in mismatch_details:
                    print(f"      - {detail}")
        
        # Check foreign keys
        print("\nForeign Key Analysis:")
        model_fks = {const.name: const for const in table.foreign_key_constraints}
        db_fks = inspector.get_foreign_keys(table_name)
        
        for fk in db_fks:
            print(f"FK: {fk['constrained_columns']} -> {fk['referred_table']}.{fk['referred_columns']}")
            print(f"   OnDelete: {fk.get('options', {}).get('ondelete', 'NO ACTION')}")

def check_enum_values():
    print("\n=== Checking Enum Values ===\n")
    
    # Check BugStatus values in database
    with engine.connect() as conn:
        status_values = conn.execute(text("SELECT DISTINCT status FROM bug_reports")).fetchall()
        print("Bug Status values in DB:", [status[0] for status in status_values])
        
        severity_values = conn.execute(text("SELECT DISTINCT severity FROM bug_reports")).fetchall()
        print("Severity values in DB:", [severity[0] for severity in severity_values])

if __name__ == "__main__":
    check_tables_detailed()
    check_enum_values()