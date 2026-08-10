import sys
from pathlib import Path

# The probe lives in a sibling directory and is not a package — its path is
# added so document parsing is tested with the very code that runs on points.
XPROBE = Path(__file__).resolve().parents[2] / "agent"
sys.path.insert(0, str(XPROBE))
