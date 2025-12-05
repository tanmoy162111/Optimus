"""
Config package - re-exports Config class from config.py
This fixes the import conflict between config/ folder and config.py

The issue: Python finds this config/ folder before config.py, causing
ImportError: cannot import name 'Config' from 'config'

Solution: This __init__.py re-exports Config from the parent config.py
"""
import importlib.util
from pathlib import Path

# Get the backend directory (parent of this config folder)
backend_dir = Path(__file__).parent.parent

# Load config.py as a module
spec = importlib.util.spec_from_file_location("config_module", backend_dir / "config.py")
config_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config_module)

# Re-export Config class
Config = config_module.Config

__all__ = ['Config']
