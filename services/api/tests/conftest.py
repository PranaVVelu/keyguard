import sys
from pathlib import Path

# Make `app` and the test helpers importable without packaging the service.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
