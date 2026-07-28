from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.config import ConfigError, load_settings


def test_repository_config_cannot_widen_security(tmp_path: Path) -> None:
    """A repository must not be able to enable shell execution through configuration."""
    (tmp_path / "pyquality.toml").write_text(
        "[security]\nallow_shell=true\n", encoding="utf-8"
    )

    with pytest.raises(ConfigError, match="unknown field"):
        load_settings(tmp_path, None)


def test_defaults_are_exact(tmp_path: Path) -> None:
    """Relaxing the secure default limits would allow unbounded harness work."""
    settings = load_settings(tmp_path, None)

    assert (settings.round_limit, settings.global_concurrency) == (8, 2)
    assert settings.global_concurrency <= 4


def test_repository_config_cannot_relax_a_user_timeout(tmp_path: Path) -> None:
    """A repository must not increase a timeout chosen by the invoking user."""
    user_file = tmp_path / "user.toml"
    user_file.write_text("subprocess_timeout_s = 20\n", encoding="utf-8")
    (tmp_path / "pyquality.toml").write_text("subprocess_timeout_s = 30\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="cannot widen"):
        load_settings(tmp_path, user_file)


def test_pyproject_configuration_is_not_a_repository_configuration_source(tmp_path: Path) -> None:
    """Reading pyproject settings would let packaging metadata alter harness policy."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pyquality]\nround_limit = 1\n", encoding="utf-8"
    )

    assert load_settings(tmp_path, None).round_limit == 8


def test_user_configuration_rejects_arbitrary_pytest_flags(tmp_path: Path) -> None:
    """Allowing arbitrary flags would permit a user config to inject unsafe execution behavior."""
    user_file = tmp_path / "user.toml"
    user_file.write_text('pytest_args = ["--capture=no"]\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid configuration"):
        load_settings(tmp_path, user_file)


def test_repository_can_add_but_not_replace_exclusions(tmp_path: Path) -> None:
    """Replacing exclusions would silently discard user-selected safety boundaries."""
    user_file = tmp_path / "user.toml"
    user_file.write_text('exclusions = [".venv"]\n', encoding="utf-8")
    (tmp_path / "pyquality.toml").write_text('exclusions = ["vendor"]\n', encoding="utf-8")

    assert load_settings(tmp_path, user_file).exclusions == (".venv", "vendor")
