import os
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from database import engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_migrations():
    # Get Alembic configuration
    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    
    # Get current database revision
    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        current_rev = context.get_current_revision()
    
    logger.info(f"Current database revision: {current_rev}")
    
    # Get all migrations
    migrations = []
    for sc in script.walk_revisions():
        migrations.append({
            'revision': sc.revision,
            'down_revision': sc.down_revision,
            'dependencies': sc.dependencies,
            'description': sc.doc,
            'module': sc._module
        })
    
    logger.info("\nMigration Chain:")
    for m in reversed(migrations):
        logger.info(f"↓ {m['revision']} - {m['description']}")
        if m['dependencies']:
            logger.info(f"  Dependencies: {m['dependencies']}")
    
    # Check for potential issues
    heads = script.get_heads()
    if len(heads) > 1:
        logger.warning(f"\n⚠️ Multiple heads detected: {heads}")
    
    # Verify migration files
    logger.info("\nMigration files:")
    for filename in os.listdir('alembic/versions'):
        if filename.endswith('.py') and not filename.startswith('__'):
            logger.info(f"📄 {filename}")

if __name__ == "__main__":
    check_migrations()
