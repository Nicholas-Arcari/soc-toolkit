import sys
from pathlib import Path

# Add backend to Python path so tests can import modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
