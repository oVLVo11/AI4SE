"""Distribution artifacts remain safe, runnable, and self-contained."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def test_required_artifacts_and_readme_headings_exist() -> None:
    required_paths = (
        "README.md",
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        "Dockerfile",
        ".dockerignore",
    )
    assert all((REPOSITORY_ROOT / path).is_file() for path in required_paths)

    readme = _read("README.md")
    for heading in (
        "## Installation",
        "## Running",
        "## Distribution",
        "## Credential Security",
        "## Project Structure",
        "## Safety Boundaries",
        "## Known Limitations",
    ):
        assert heading in readme


def test_readme_documents_safe_local_and_portable_delivery_limits() -> None:
    readme = _read("README.md")
    for text in (
        "keyring-first",
        "PYQUALITY_API_KEY",
        "plaintext",
        "pytest can execute repository code",
        "not an operating-system sandbox",
        "local SQLite and audit",
        "python -m pip install --no-deps dist\\pyquality_harness-0.1.0-py3-none-any.whl",
        "docker build -t pyquality-harness .",
        "docker run --rm -p 8000:8000 pyquality-harness",
        "### Render-compatible deployment",
        "No hosted deployment is provided",
    ):
        assert text in readme


def test_ci_files_define_the_course_commands_and_triggers() -> None:
    github_ci = _read(".github/workflows/ci.yml")
    assert re.search(r"(?m)^on:\s*\n\s+push:\s*\n\s+pull_request:", github_ci)
    assert "python-version: \"3.12\"" in github_ci
    for command in (
        "pytest -q",
        "ruff check src tests",
        "python -m build",
        "docker build",
    ):
        assert command in github_ci
    assert ".[dev]" in github_ci

    gitlab_ci = _read(".gitlab-ci.yml")
    assert re.search(r"(?m)^unit-test:\s*$", gitlab_ci)
    assert "image: python:3.12-slim" in gitlab_ci
    assert "-e \".[dev]\"" in gitlab_ci
    assert "pytest -q" in gitlab_ci


def test_pyproject_declares_buildable_python_package_contract() -> None:
    project = tomllib.loads(_read("pyproject.toml"))
    assert project["project"]["requires-python"] == ">=3.12"
    assert project["build-system"]["build-backend"] == "hatchling.build"
    assert any(requirement.startswith("hatchling>=1.25") for requirement in project["build-system"]["requires"])
    assert project["project"]["scripts"]["pyquality"] == "pyquality.cli:main"
    assert any(
        dependency.startswith("build>=1.2")
        for dependency in project["project"]["optional-dependencies"]["dev"]
    )
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/pyquality"]


def test_wheel_contains_runtime_assets_but_no_development_or_data_residue(tmp_path: Path) -> None:
    distribution_directory = tmp_path / "dist"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        env=environment,
    )
    wheel_path = next(distribution_directory.glob("*.whl"))
    with zipfile.ZipFile(wheel_path) as wheel:
        contents = set(wheel.namelist())

    assert {
        "pyquality/web/templates/approval.html",
        "pyquality/web/templates/base.html",
        "pyquality/web/templates/settings.html",
        "pyquality/web/templates/task_detail.html",
        "pyquality/web/templates/tasks_new.html",
        "pyquality/demo_fixture/__init__.py",
        "pyquality/demo_fixture/calculator.py",
        "pyquality/demo_fixture/pyproject.toml",
        "pyquality/demo_fixture/test_calculator.py",
    } <= contents
    prohibited_prefixes = ("tests/", ".git/", ".superpowers/")
    assert not any(name.startswith(prohibited_prefixes) for name in contents)
    assert not any(
        name.endswith((".db", ".sqlite", ".log"))
        or "/audit/" in name
        or "/cache/" in name
        for name in contents
    )


def test_sdist_excludes_development_and_local_data_but_keeps_runtime_inputs(
    tmp_path: Path,
) -> None:
    distribution_directory = tmp_path / "dist"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
    )
    with tarfile.open(next(distribution_directory.glob("*.tar.gz"))) as sdist:
        contents = sdist.getnames()

    assert any(name.endswith("/pyproject.toml") for name in contents)
    assert any(name.endswith("/README.md") for name in contents)
    assert any(name.endswith("/src/pyquality/web/templates/base.html") for name in contents)
    assert any(name.endswith("/src/pyquality/demo_fixture/calculator.py") for name in contents)
    assert not any(
        (relative_parts := Path(name).parts[1:])[:1] in {("examples",), ("tests",)}
        or any(part in {".git", ".superpowers", "__pycache__"} for part in relative_parts)
        or name.endswith((".db", ".sqlite", ".sqlite3", ".log"))
        or "/audit/" in name
        or "/cache/" in name
        for name in contents
    )


def test_dockerfile_builds_and_runs_only_the_public_mock_distribution() -> None:
    dockerfile = _read("Dockerfile")
    assert re.search(r"(?mi)^FROM\s+python:3\.12-slim\s+AS\s+builder\s*$", dockerfile)
    assert re.search(r"(?mi)^FROM\s+python:3\.12-slim\s+AS\s+runtime\s*$", dockerfile)
    assert "python -m build --wheel --no-isolation" in dockerfile
    assert re.search(r"pip install --no-cache-dir /tmp/dist/.*\.whl", dockerfile)
    assert "ENV PYQUALITY_MODE=public_mock" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert (
        'CMD ["pyquality", "serve", "--host", "0.0.0.0", "--port", "8000", "--public-mock"]'
        in dockerfile
    )
    assert not re.search(r"(?i)\b(ARG|ENV)\b.*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", dockerfile)
    assert "pip install -e" not in dockerfile
    assert "COPY tests" not in dockerfile
    assert "provider" not in dockerfile.lower()


def test_dockerignore_excludes_development_and_sensitive_local_data() -> None:
    ignored_paths = {
        line.strip()
        for line in _read(".dockerignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {
        ".git",
        ".superpowers",
        ".worktrees",
        "__pycache__/",
        ".pytest_cache/",
        ".ruff_cache/",
        "tests/",
        "dist/",
        "build/",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "*.log",
        "audit/",
        "cache/",
        "AI4SE_Final_Project_A_Coding_Agent_Harness.md",
        "通用要求.md",
    } <= ignored_paths
    assert "pyproject.toml" not in ignored_paths
    assert "src/" not in ignored_paths
