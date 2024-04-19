# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import pytest

try:
    import PyQt6
    have_pyqt6 = True
except ImportError:
    have_pyqt6 = False

try:
    import pytestqt
    have_pqtestqt = True
except ImportError:
    have_pqtestqt = False


def pytest_ignore_collect(collection_path: pathlib.Path, path,
                          config: pytest.Config) -> bool | None:

    """Ignore GUI tests if DISPLAY is not set or PyQt is not available."""

    xdisp = bool(os.getenv("DISPLAY"))

    # Return True to prevent considering this path for collection.
    if all((xdisp, have_pyqt6, have_pqtestqt)):
        return False

    return True
