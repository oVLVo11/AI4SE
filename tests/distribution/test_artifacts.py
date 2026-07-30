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

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TASK_12_QUALITY_REVIEW = (
    "Task 1 review CLEAN; Task 2 review pending; focused 12 passed; "
    "full isolated 593 passed, 10 skipped; wheel/sdist and wheel CLI/demo verified; "
    "Docker CLI unavailable"
)


def _read(relative_path: str) -> str:
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def _task_ledger_rows(plan: str) -> dict[str, tuple[str, str, str, str, str]]:
    header = "| Task | Status | Implementing agent | Spec review | Quality review | Commit |"
    table = plan[plan.index(header) :]
    rows: dict[str, tuple[str, str, str, str, str]] = {}
    for line in table.splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) == 6:
            rows[cells[0]] = tuple(cells[1:])  # type: ignore[assignment]
    return rows


def _validate_root_evidence(plan: str, agent_log: str) -> None:
    ledger = _task_ledger_rows(plan)
    for task in ("11", "11A", "11B", "12"):
        assert task in ledger
        status, agent, spec_review, quality_review, commits = ledger[task]
        assert all((status, agent, spec_review, quality_review, commits))
        assert agent == "unavailable" or re.fullmatch(r"`/root/[^`]+`(?:, `/root/[^`]+`)*", agent)
        assert re.search(r"\b[0-9a-f]{7,40}\b", commits)

    assert ledger["11"][0] == "Implemented; breaker reached"
    assert ledger["11A"][0] == "Blocked; breaker reached"
    assert ledger["11B"][0] == "Complete"
    assert "CLEAN" in ledger["11B"][2]
    assert ledger["12"][0] == "In progress; Task 1 clean, Task 2 under review"
    assert "Task 2 review pending" in ledger["12"][2]
    assert "breaker" in ledger["11"][2].lower()
    assert "breaker" in ledger["11"][3].lower()
    assert "clean" not in ledger["11"][2].lower()
    assert "clean" not in ledger["11"][3].lower()
    assert "fifth review" in ledger["11A"][2].lower()
    assert "breaker" in ledger["11A"][3].lower()
    assert "clean" not in ledger["11A"][2].lower()
    assert "clean" not in ledger["11A"][3].lower()
    assert "CLEAN" in ledger["11B"][2]
    assert "CLEAN" in ledger["11B"][3]
    assert "Task 1 clean" in ledger["12"][0]
    assert "Task 2 under review" in ledger["12"][0]
    assert "CLEAN" in ledger["12"][2]
    assert "Task 2 review pending" in ledger["12"][2]
    assert ledger["12"][3].strip() == EXPECTED_TASK_12_QUALITY_REVIEW

    required_commits = {
        "11": (
            "593384e", "e80a17d", "6dcc2ec", "16b4edc", "ba8d95b", "d60a8bc", "10339c0",
            "7c21ce6", "39a21c4", "5ad427a", "f363ccc", "90b9c45", "9f44513",
        ),
        "11A": ("87e5ad7", "63b08cf", "07cffcd", "5eb42fb", "ea569a9", "47bed5d", "6de2411"),
        "11B": ("d396c24", "e7448ff", "cad8e17"),
        "12": ("6d06a3e", "783a814", "869dd20", "8e1792d"),
    }
    for task, expected in required_commits.items():
        actual = tuple(re.findall(r"\b[0-9a-f]{7,40}\b", ledger[task][4]))
        assert actual == expected

    headings = (
        "## 2026-07-29 Task 11 implementation and breaker",
        "## 2026-07-30 Task 11A remediation and breaker",
        "## 2026-07-30 Task 11B remediation and CLEAN review",
        "## 2026-07-30 Task 12 distribution work",
    )
    heading_positions = [agent_log.index(heading) for heading in headings]
    assert heading_positions == sorted(heading_positions)

    task_11 = agent_log[heading_positions[0] : heading_positions[1]].lower()
    task_11a = agent_log[heading_positions[1] : heading_positions[2]].lower()
    task_11b = agent_log[heading_positions[2] : heading_positions[3]]
    assert "breaker" in task_11
    assert "breaker" in task_11a
    assert "remaining" in task_11b.lower() and "defect" in task_11b.lower()
    assert "CLEAN" in task_11b
    for commit in ("6de2411", "cad8e17", "6d06a3e", "783a814", "869dd20", "8e1792d"):
        assert commit in agent_log


def test_root_evidence_records_preserve_task_11_breakers_and_task_12_review_state() -> None:
    _validate_root_evidence(_read("PLAN.md"), _read("AGENT_LOG.md"))


@pytest.mark.parametrize(
    ("path", "old", "new"),
    (
        ("PLAN.md", "Implemented; breaker reached", "Complete; CLEAN"),
        ("PLAN.md", "Blocked; breaker reached", "Complete; CLEAN"),
        ("PLAN.md", "In progress; Task 1 clean, Task 2 under review", "Complete; CLEAN"),
        ("PLAN.md", "`6d06a3e`, `783a814`, `869dd20`, `8e1792d`", "`deadbee`"),
        ("AGENT_LOG.md", "`783a814`", "`amendment unavailable`"),
    ),
)
def test_root_evidence_contract_rejects_reviewed_history_mutations(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    old: str,
    new: str,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    documents[path] = documents[path].replace(old, new)

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_root_evidence_records_preserve_task_11_breakers_and_task_12_review_state()


@pytest.mark.parametrize(
    ("path", "replacements"),
    (
        (
            "PLAN.md",
            (("`6d06a3e`, `783a814`, `869dd20`, `8e1792d`", "`6d06a3e`, `783a814`, `869dd20`, `8e1792d`, `deadbee`"),),
        ),
        (
            "PLAN.md",
            (("Five-round review breaker", "CLEAN"), ("517 passed, 9 skipped; five-round breaker", "CLEAN")),
        ),
        (
            "PLAN.md",
            (("Task and final review CLEAN; focused durability 11 passed; affected 128 passed, 4 skipped; full 581 passed, 10 skipped; Ruff and diff clean", "FAILED"),),
        ),
    ),
)
def test_root_evidence_contract_rejects_false_commits_and_review_verdicts(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    replacements: tuple[tuple[str, str], ...],
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    for old, new in replacements:
        documents[path] = documents[path].replace(old, new)

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_root_evidence_records_preserve_task_11_breakers_and_task_12_review_state()


def test_root_evidence_contract_rejects_completed_task_12_and_docker_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    documents["PLAN.md"] = documents["PLAN.md"].replace(
        "Task 1 review CLEAN; Task 2 review pending; focused 12 passed; full isolated 593 passed, 10 skipped; wheel/sdist and wheel CLI/demo verified; Docker CLI unavailable",
        "Task 12 COMPLETE; Docker image build succeeded",
    )

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_root_evidence_records_preserve_task_11_breakers_and_task_12_review_state()


@pytest.mark.parametrize(
    "contradiction",
    (
        "Docker build succeeded",
        "Task 12 finished and final review passed",
    ),
)
def test_root_evidence_contract_rejects_appended_task_12_quality_contradictions(
    monkeypatch: pytest.MonkeyPatch,
    contradiction: str,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    current_quality_review = (
        "Task 1 review CLEAN; Task 2 review pending; focused 12 passed; "
        "full isolated 593 passed, 10 skipped; wheel/sdist and wheel CLI/demo verified; "
        "Docker CLI unavailable"
    )
    documents["PLAN.md"] = documents["PLAN.md"].replace(
        current_quality_review,
        f"{current_quality_review}; {contradiction}",
    )

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_root_evidence_records_preserve_task_11_breakers_and_task_12_review_state()


def test_root_evidence_contract_does_not_require_git_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_git(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("root evidence validation must not invoke Git")

    monkeypatch.setattr(subprocess, "run", unavailable_git)
    _validate_root_evidence(_read("PLAN.md"), _read("AGENT_LOG.md"))


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
