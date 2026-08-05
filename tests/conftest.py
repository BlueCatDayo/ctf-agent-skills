"""Test fixtures and shared setup for Stage 2 tests."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure the challenges/test directory exists for integration tests
CHALLENGES_TEST_DIR = Path(__file__).parent.parent / "challenges" / "test"


def ensure_test_workspace():
    """Create the test workspace with fixture files if needed."""
    CHALLENGES_TEST_DIR.mkdir(parents=True, exist_ok=True)

    # Copy fixtures if they don't exist
    fixtures_dir = Path(__file__).parent / "fixtures"

    for fixture_name in ["test_text.txt", "test_encoded.b64", "test_binary.bin"]:
        src = fixtures_dir / fixture_name
        dst = CHALLENGES_TEST_DIR / fixture_name
        if src.exists() and not dst.exists():
            import shutil
            shutil.copy2(src, dst)


ensure_test_workspace()
