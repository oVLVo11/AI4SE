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


def test_user_configuration_rejects_string_values_for_integer_limits(tmp_path: Path) -> None:
    """Coercing TOML strings would let malformed user settings silently change execution limits."""
    user_file = tmp_path / "user.toml"
    user_file.write_text('round_limit = "4"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="wrong type"):
        load_settings(tmp_path, user_file)


def test_byte_limit_defaults_are_exact(tmp_path: Path) -> None:
    """Changing named byte defaults would weaken the reviewed public-input boundaries."""
    settings = load_settings(tmp_path, None)

    assert (
        settings.max_rationale_bytes,
        settings.max_finding_summary_bytes,
        settings.max_finding_evidence_bytes,
        settings.max_group_key_bytes,
        settings.max_action_arguments_bytes,
        settings.max_tool_output_bytes,
        settings.max_tool_metadata_bytes,
        settings.max_config_pattern_bytes,
        settings.max_config_patterns,
        settings.source_excerpt_bytes,
        settings.feedback_total_bytes,
    ) == (4_096, 1_024, 4_096, 512, 65_536, 65_536, 16_384, 1_024, 128, 8_192, 32_768)


def test_user_configuration_rejects_oversized_or_too_many_redaction_patterns(tmp_path: Path) -> None:
    """Unbounded configuration patterns would exceed the reviewed redaction-input budget."""
    oversized_file = tmp_path / "oversized.toml"
    oversized_file.write_text(f'redaction_patterns = ["{"x" * 1_025}"]\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid configuration"):
        load_settings(tmp_path, oversized_file)

    count_file = tmp_path / "count.toml"
    count_file.write_text("redaction_patterns = [" + ", ".join('"x"' for _ in range(129)) + "]\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid configuration"):
        load_settings(tmp_path, count_file)


def test_repository_can_only_lower_a_byte_cap(tmp_path: Path) -> None:
    """A repository must not increase the reviewed action-argument byte cap."""
    (tmp_path / "pyquality.toml").write_text("max_action_arguments_bytes = 65537\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="cannot widen"):
        load_settings(tmp_path, None)


@pytest.mark.parametrize(
    "field, value",
    [
        ("exclusions", '["ééééééééé"]'),
        ("pytest_args", '["ééééééééé"]'),
        ("ruff_args", '["ééééééééé"]'),
    ],
)
def test_lowered_path_cap_rejects_config_paths(tmp_path: Path, field: str, value: str) -> None:
    """Skipping the configured UTF-8 path cap would admit oversized path inputs."""
    (tmp_path / "pyquality.toml").write_text("max_config_pattern_bytes = 16\n", encoding="utf-8")
    user_file = tmp_path / "user.toml"
    user_file.write_text(f"{field} = {value}\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid configuration"):
        load_settings(tmp_path, user_file)
