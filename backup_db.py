import shutil
import os
from datetime import datetime
from database import DATABASE_URL
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def backup_database():
    """Create a timestamped backup of the SQLite database."""
    try:
        # Get the database path from DATABASE_URL
        db_path = DATABASE_URL.replace('sqlite:///', '')
        
        # Create backups directory if it doesn't exist
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            logger.info(f"Created backup directory: {backup_dir}")
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create backup filename
        backup_filename = f"bug_reports_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Copy the database file
        shutil.copy2(db_path, backup_path)
        
        # Get file size
        file_size = os.path.getsize(backup_path) / (1024 * 1024)  # Convert to MB
        
        logger.info(f"✅ Database backup created successfully!")
        logger.info(f"📁 Location: {backup_path}")
        logger.info(f"📊 Size: {file_size:.2f} MB")
        
        # List all backups
        backups = sorted([f for f in os.listdir(backup_dir) if f.endswith('.db')])
        logger.info(f"\n📚 Available backups:")
        for backup in backups:
            backup_size = os.path.getsize(os.path.join(backup_dir, backup)) / (1024 * 1024)
            logger.info(f"   - {backup} ({backup_size:.2f} MB)")
            
    except Exception as e:
        logger.error(f"❌ Backup failed: {str(e)}")
        raise

if __name__ == "__main__":
    backup_database() 