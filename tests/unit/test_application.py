from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.application import build_service
from pyquality.service import HarnessService, PreflightError


def test_production_composition_builds_offline_repository_scoped_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Backend:
        priority = 1

        def get_password(self, service: str, account: str) -> None:
            return None

        def set_password(self, service: str, account: str, value: str) -> None:
            pass

        def delete_password(self, service: str, account: str) -> None:
            pass

    repo = tmp_path / "repo"
    other = tmp_path / "other"
    repo.mkdir()
    other.mkdir()
    monkeypatch.setattr("pyquality.application.keyring.get_keyring", Backend)

    service = build_service(repo, provider="mock")

    assert isinstance(service, HarnessService)
    with pytest.raises(PreflightError, match="scope"):
        service.create_task(other, "must not cross repositories")
