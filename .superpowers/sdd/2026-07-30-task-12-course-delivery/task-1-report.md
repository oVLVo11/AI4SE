# Task 1 report — executable distribution contract

Execution/review base: `80e77d1`

## Scope delivered

- Added the distribution contract test suite at `tests/distribution/test_artifacts.py`.
- Added the required README, GitHub Actions workflow, GitLab CI configuration, multi-stage Dockerfile, and Docker ignore rules.
- Kept `pyproject.toml` unchanged: the required wheel contents were already present in the existing hatch configuration.

## TDD evidence

Initial file/README/CI RED command:

```powershell
python -m pytest tests/distribution/test_artifacts.py -k 'required_artifacts or ci_files' --basetemp "$env:TEMP\pyquality-task12-red-files"
```

Result: `2 failed, 4 deselected`. The required files were absent and reading `.github/workflows/ci.yml` raised `FileNotFoundError`.

Package/container RED command:

```powershell
python -m pytest tests/distribution/test_artifacts.py -k 'wheel_contains or dockerfile_builds' --basetemp "$env:TEMP\pyquality-task12-red-package-container"
```

Result: Docker contract test failed with `FileNotFoundError` for `Dockerfile`; the wheel test was already green because the pre-existing hatch configuration includes the required runtime assets and excludes residue.

GREEN command:

```powershell
python -m pytest tests/distribution/test_artifacts.py --basetemp "$env:TEMP\pyquality-task12-green-distribution"
```

Result: `6 passed`.

## Final verification

- `python -m build --no-isolation --outdir %TEMP%\pyquality-task12-package` built `pyquality_harness-0.1.0.tar.gz` (296,997 bytes) and `pyquality_harness-0.1.0-py3-none-any.whl` (108,082 bytes) outside the repository.
- Bounded archive inspection found both template and demo-fixture assets, with no tests, Git/SDD, database, audit, cache, or log residue in either archive.
- Wheel SHA-256: `4D9101A7D0476C7485D58F616BF8252EFCC7604056D89B5A52B2882B8F612ABF`.
- A fresh `%TEMP%\pyquality-task12-wheel-venv` created with `--system-site-packages` installed the wheel using `--no-deps` outside the repository. `pyquality.__file__` resolved in that venv; `pyquality --help` and `pyquality demo --json` succeeded without credentials or network activity.
- `docker version` was attempted and failed with PowerShell `CommandNotFoundException`: Docker CLI is absent on this controller. Docker image build success is therefore not claimed; GitHub CI retains `docker build` coverage.
- `python -m pytest --basetemp "$env:TEMP\pyquality-task12-final-pytest"`: `587 passed, 10 skipped`.
- `ruff check src tests`: passed after removing one unused test import detected by the initial lint run.
- Focused secret scan over the package and owned delivery files returned no credential-pattern matches.
- `git diff --check`: passed before staging; staged diff check is recorded before commit.

## Frozen cumulative review package

`task-1-cumulative-review.zip` contains the binary diff from `80e77d1` for the six delivery-contract files. It is 4,138 bytes and has SHA-256 `15432A6736732D5E653DBB19D8E81698FE3E75E2F2D9BB60917B2805C0F7D389`.

## Concern

Docker is unavailable on the controller, so a local image build was not possible. This is an environment limitation, not a skipped CI contract.
