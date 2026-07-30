# Hermetic sdist Test Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the sdist exclusion regression copy only explicit package build inputs so inaccessible untracked workspace residue cannot affect it.

**Architecture:** Introduce one test-only source-copy helper that builds a minimal isolated Hatch source tree from explicit files/directories. Preserve the existing `.venv-sentinel` archive mutation proof and keep production packaging configuration unchanged.

**Tech Stack:** Python 3.12+, pathlib, shutil, tarfile, pytest, Hatchling/build, Ruff.

## Global Constraints

- Do not delete, chmod, traverse, stage, or otherwise modify existing `.pytest-task*` residue or user documents.
- Do not use Git to construct the isolated source tree.
- Do not modify production source, `pyproject.toml`, `.gitignore`, `.dockerignore`, or package contents.
- Required inputs must fail loudly if absent; no silent skipping.
- Follow RED → GREEN and obtain review before pushing.

---

### Task 1: Copy Explicit sdist Build Inputs

**Files:**
- Modify: `tests/distribution/test_artifacts.py`

**Interfaces:**
- Consumes: `REPOSITORY_ROOT`, `tmp_path`, current Hatch sdist build helper, and existing archive assertions.
- Produces: `_copy_sdist_source(source_root: Path) -> None`, used only by the hermetic sdist exclusion regression.

- [ ] **Step 1: Capture the existing environmental RED**

From the main workspace, run:

```powershell
python -m pytest -p no:cacheprovider tests/distribution/test_artifacts.py::test_sdist_excludes_development_and_local_data_but_keeps_runtime_inputs -q
```

Expected: FAIL in `shutil.copytree(REPOSITORY_ROOT, ...)` with `WinError 5` while traversing an inaccessible `.pytest-task*` directory.

- [ ] **Step 2: Add a failing helper-boundary test**

Add a focused test that monkeypatches `REPOSITORY_ROOT` to a fixture repository containing the required files plus an unrelated root directory. Monkeypatch `shutil.copytree` to allow only the exact `fixture_root / "src"` call and fail on any root-wide traversal. The helper test must require these copied outputs:

```python
assert (source_root / "pyproject.toml").is_file()
assert (source_root / "README.md").is_file()
assert (source_root / "src" / "pyquality" / "public_demo_worker.py").is_file()
assert (source_root / "src" / "pyquality" / "web" / "templates").is_dir()
assert (source_root / "src" / "pyquality" / "demo_fixture").is_dir()
```

Run the new test and require RED because `_copy_sdist_source` does not exist.

- [ ] **Step 3: Implement the minimal explicit-copy helper**

Implement in `tests/distribution/test_artifacts.py`:

```python
def _copy_sdist_source(source_root: Path) -> None:
    source_root.mkdir()
    for filename in ("pyproject.toml", "README.md"):
        shutil.copy2(REPOSITORY_ROOT / filename, source_root / filename)
    shutil.copytree(REPOSITORY_ROOT / "src", source_root / "src")
```

If package metadata directly references a root license file, add its exact filename to the tuple after verifying the reference. Do not enumerate all root entries or add fallback globbing.

- [ ] **Step 4: Replace the whole-repository copy and verify GREEN**

Change only `test_sdist_excludes_development_and_local_data_but_keeps_runtime_inputs` to call `_copy_sdist_source(source_root)`, then create `.venv-sentinel/marker` exactly as before.

Run:

```powershell
python -m pytest -p no:cacheprovider tests/distribution/test_artifacts.py -q
```

Expected: all distribution tests PASS from both the isolated worktree and the dirty main workspace.

- [ ] **Step 5: Mutation-check the virtualenv exclusion**

In the isolated copied `pyproject.toml`, temporarily remove the literal `/.venv*` exclusion before building. Require the existing archive-component assertion to fail because `.venv-sentinel/marker` enters the sdist. Restore the exclusion and rerun GREEN. Do not commit the mutation.

- [ ] **Step 6: Run full verification**

Run from the final tracked tree:

```powershell
python -m pytest -p no:cacheprovider -q
python -m ruff check src tests
git diff --check
```

Then run the exact target test from the main workspace to prove inaccessible residue no longer affects it.

- [ ] **Step 7: Commit and prepare review**

```powershell
git add tests/distribution/test_artifacts.py
git commit -m "test: isolate sdist source fixture"
```

Generate a frozen review package. Do not push until spec and quality review are clean.
