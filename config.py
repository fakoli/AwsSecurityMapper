import os
from pathlib import Path

# Cache configuration
CACHE_DIR = Path(os.path.expanduser("~/.aws-sg-mapper/cache"))
CACHE_DURATION = 3600  # Cache validity in seconds

# AWS configuration
DEFAULT_REGION = "us-east-1"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# Graph visualization settings
NODE_SIZE = 2000
FONT_SIZE = 8
EDGE_WIDTH = 1
