from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from pyquality import security


@pytest.fixture(scope="session", autouse=True)
def isolated_audit_index_root() -> Iterator[None]:
    """Keep durable audit-index test artifacts inside one session-owned directory."""
    previous_environment = os.environ.get("PYQUALITY_AUDIT_INDEX_ROOT")
    previous_default = security._DEFAULT_AUDIT_INDEX_BASE
    with TemporaryDirectory(prefix="pyquality-test-audit-index-") as directory:
        root = Path(directory) / "index"
        os.environ["PYQUALITY_AUDIT_INDEX_ROOT"] = str(root)
        security._DEFAULT_AUDIT_INDEX_BASE = root
        try:
            yield
        finally:
            security._DEFAULT_AUDIT_INDEX_BASE = previous_default
            if previous_environment is None:
                os.environ.pop("PYQUALITY_AUDIT_INDEX_ROOT", None)
            else:
                os.environ["PYQUALITY_AUDIT_INDEX_ROOT"] = previous_environment
