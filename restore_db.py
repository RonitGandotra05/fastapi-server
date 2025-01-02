import shutil
import os
from database import DATABASE_URL
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def list_backups():
    """List all available backups."""
    backup_dir = 'backups'
    if not os.path.exists(backup_dir):
        logger.error("No backups directory found!")
        return []
    
    backups = sorted([f for f in os.listdir(backup_dir) if f.endswith('.db')])
    return backups

def restore_backup(backup_name):
    """Restore database from a backup."""
    try:
        backup_dir = 'backups'
        backup_path = os.path.join(backup_dir, backup_name)
        db_path = DATABASE_URL.replace('sqlite:///', '')
        
        # Create backup of current database before restoring
        current_backup = f"pre_restore_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(db_path, os.path.join(backup_dir, current_backup))
        logger.info(f"Created safety backup: {current_backup}")
        
        # Restore the selected backup
        shutil.copy2(backup_path, db_path)
        logger.info(f"✅ Successfully restored from backup: {backup_name}")
        
    except Exception as e:
        logger.error(f"❌ Restore failed: {str(e)}")
        raise

if __name__ == "__main__":
    print("\nAvailable backups:")
    backups = list_backups()
    for i, backup in enumerate(backups, 1):
        print(f"{i}. {backup}")
    
    if backups:
        try:
            choice = int(input("\nEnter the number of the backup to restore (0 to cancel): "))
            if 0 < choice <= len(backups):
                restore_backup(backups[choice-1])
            elif choice == 0:
                print("Restore cancelled.")
            else:
                print("Invalid choice!")
        except ValueError:
            print("Please enter a valid number!")
    else:
        print("No backups available!") 