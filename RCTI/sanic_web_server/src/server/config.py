import logging
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Neo4j configuration
# NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
# NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
# NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jpassword")

# Configure the storage path
STORAGE_PATH = Path(os.getenv("STORAGE_PATH", "/home/mgmt/attackflow/sanic_web_server/alerts"))
STIX_STORAGE_PATH = Path(os.getenv("STIX_STORAGE_PATH", "/home/mgmt/attackflow/docs"))
ATTACKFLOW_FILE = os.getenv("RULES_FILE", "/home/mgmt/attackflow/sanic_web_server/docs/attackflow_graphs/Resilmesh-RCTI-UberMicroEmulation.json")

# Debug flag for correlation engine
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

def debug_print(*args, **kwargs):
    """Print debug messages only when DEBUG is True"""
    if DEBUG:
        logger.debug(*args, **kwargs)