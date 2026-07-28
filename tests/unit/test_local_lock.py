from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path syntax")
def test_windows_unc_lock_path_uses_unc_extended_prefix() -> None:
    from pyquality.storage.local_lock import _windows_extended_path

    converted = _windows_extended_path(Path(r"\\server\share\locks\key.lock"))

    assert str(converted) == r"\\?\UNC\server\share\locks\key.lock"
