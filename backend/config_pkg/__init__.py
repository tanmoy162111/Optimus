# Expose the Config class from the config module
import sys
import os
from pathlib import Path

# Add the backend directory to the path so we can import config.py
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Now we can import Config from config.py
from config import Config

# Make Config available when importing from config_pkg
__all__ = ['Config']