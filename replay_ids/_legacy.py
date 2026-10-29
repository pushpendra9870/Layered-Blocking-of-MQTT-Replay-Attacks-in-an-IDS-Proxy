"""Makes the ORIGINAL, unmodified external_eval modules importable
(mqtt_io, signing, detectors, score) so the new code reuses them."""
import sys
from pathlib import Path

LEGACY_DIR = Path(__file__).resolve().parent.parent / "external_eval"
if str(LEGACY_DIR) not in sys.path:
    sys.path.insert(0, str(LEGACY_DIR))
