# Task 12 Course Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce evidence-backed course documentation, installable wheel/sdist artifacts, executable CI definitions, and a mock-only container contract for PyQuality Harness.

**Architecture:** Distribution tests define the required artifact surface before implementation. Task 1 creates README, package, CI, and container artifacts and verifies the built distribution; Task 2 then synchronizes only already-proven Task 11/11A/11B and Task 12 evidence into the root course records.

**Tech Stack:** Python 3.12+, hatchling/PEP 517, pytest, Ruff, GitHub Actions, GitLab CI, multi-stage Docker builds, Markdown, YAML.

## Global Constraints

- Implement `docs/superpowers/specs/2026-07-30-task-12-course-delivery-design.md` exactly.
- Work in a Superpowers-owned isolated worktree created from the resolved plan commit; record that exact execution/review base before dispatch.
- No production, packaging, CI, or documentation artifact change before the corresponding literal failing contract test is run and recorded.
- Do not modify application behavior, public APIs, security policy, audit formats, Task 11B durability logic, or deterministic demo semantics.
- Do not edit or stage the untracked source documents `AI4SE_Final_Project_A_Coding_Agent_Harness.md` and `通用要求.md`.
- Do not enumerate, modify, stage, or delete inaccessible pytest residue directories.
- Do not claim a hosted URL, remote CI success, published package/image, or Docker build that was not actually observed.
- The container contract is `PYQUALITY_MODE=public_mock`, port 8000, and `pyquality serve --host 0.0.0.0 --port 8000 --public-mock`; it contains no provider credential.
- Root evidence documents preserve the historical Task 11/11A breakers and record Task 11B as the remediation; history is appended, not rewritten.
- Task 13 remains locked until Task 12 receives task reviews and a broad final review with no open Critical or Important findings.

---

### Task 1: Executable Distribution, CI, README, and Container Contract

**Files:**
- Create: `tests/distribution/test_artifacts.py`
- Create: `README.md`
- Create: `.github/workflows/ci.yml`
- Create: `.gitlab-ci.yml`
- Create: `Dockerfile`
- Create: `.dockerignore`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `pyquality` console script, `pyquality.web.templates`, `pyquality.demo_fixture`, and `pyquality demo --json` from the completed application.
- Produces: wheel/sdist build metadata, delivery files, GitHub/GitLab CI contracts, mock-only OCI build definition, and `tests/distribution/test_artifacts.py` as their executable source-of-truth.
- The built wheel must contain `src/pyquality/web/templates/*.html` and `src/pyquality/demo_fixture/*`, and must exclude `tests/`, `.superpowers/`, `.git/`, databases, audit logs, and caches.

- [ ] **Step 1: Write file, README, and CI contract tests**

Create focused tests with repository root derived from the test file rather than the process working directory:

```python
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_course_artifacts_exist() -> None:
    required = (
        "SPEC.md",
        "PLAN.md",
        "SPEC_PROCESS.md",
        "AGENT_LOG.md",
        "README.md",
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        "Dockerfile",
        ".dockerignore",
    )
    assert not [name for name in required if not (REPO_ROOT / name).is_file()]


def test_readme_has_required_sections() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    headings = (
        "Installation",
        "Running",
        "Distribution",
        "Credential Security",
        "Project Structure",
        "Safety Boundaries",
        "Known Limitations",
    )
    assert all(f"## {heading}" in text for heading in headings)
```

Parse CI files as text and assert the exact required commands are present: `pytest -q`, `ruff check src tests`, `python -m build`, `docker build`; assert GitHub triggers contain both push and pull request. Assert `.gitlab-ci.yml` contains the exact `unit-test` job, `python:3.12-slim`, editable dev install, and pytest command.

- [ ] **Step 2: Run the first contract tests and capture RED**

```powershell
D:\Python\python.exe -m pytest tests/distribution/test_artifacts.py -k "course_artifacts or readme or ci" -v --basetemp "$env:TEMP\pyquality-task12-red-doc-ci"
```

Expected: fail because README, CI, and container delivery files are absent. Existing root course records are characterization inputs and are not modified in this step.

- [ ] **Step 3: Write package-data and container-safety contract tests**

Use `tomllib` to load `pyproject.toml`. Assert Python floor `>=3.12`, hatchling backend, `pyquality` console script, `build>=1.2,<2` in the development extra, and wheel package root `src/pyquality`.

Add a temporary wheel build that executes the current interpreter with `-m build --wheel --no-isolation --outdir <tmp>` and inspects the wheel through `zipfile.ZipFile`:

```python
required_suffixes = {
    "pyquality/web/templates/base.html",
    "pyquality/web/templates/task_detail.html",
    "pyquality/demo_fixture/calculator.py",
    "pyquality/demo_fixture/test_calculator.py",
}
names = set(archive.namelist())
assert required_suffixes <= names
assert not any(name.startswith(("tests/", ".superpowers/", ".git/")) for name in names)
```

Assert the Dockerfile has two named stages, builds and installs a wheel, sets only public mock mode, exposes 8000, and has the exact public-mock command. Reject credential-like `ENV` declarations and editable installs. Assert `.dockerignore` excludes `.git`, `.superpowers`, `.worktrees`, pytest/Ruff caches, `*.db*`, audit/log files, build artifacts, tests, and untracked course-source documents.

- [ ] **Step 4: Run package/container tests and capture RED**

```powershell
D:\Python\python.exe -m pytest tests/distribution/test_artifacts.py -k "package or wheel or docker" -v --basetemp "$env:TEMP\pyquality-task12-red-package"
```

Expected: static container tests fail because files are absent. If the wheel-content characterization already passes under hatchling, record it honestly rather than weakening it.

- [ ] **Step 5: Implement README and package metadata**

Create the seven exact README sections. Include these commands in fenced examples:

```text
python -m pip install -e ".[dev]"
pyquality demo --json
pyquality serve --host 127.0.0.1 --port 8000
python -m build
python -m pip install dist/pyquality_harness-0.1.0-py3-none-any.whl
docker build -t pyquality-harness:local .
docker run --rm -p 8000:8000 pyquality-harness:local
```

Explain keyring-first credential storage, warned `PYQUALITY_API_KEY` fallback, public mock/provider isolation, pytest execution risk, repository confinement, local-only SQLite/audit data, and the absence of hosted/remote evidence.

Keep existing project metadata and add only explicit hatch inclusion if the RED wheel test proves it necessary:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/pyquality"]

[tool.hatch.build.targets.wheel.force-include]
"src/pyquality/web/templates" = "pyquality/web/templates"
"src/pyquality/demo_fixture" = "pyquality/demo_fixture"
```

Do not duplicate an inclusion rule when the default package traversal already satisfies the archive test.

- [ ] **Step 6: Implement CI definitions**

GitHub Actions uses `actions/checkout`, `actions/setup-python` with Python 3.12, `python -m pip install -e ".[dev]"`, then separate named jobs or steps for the four required commands. The Docker job invokes:

```yaml
- name: Build mock-only image
  run: docker build -t pyquality-harness:ci .
```

Create the required GitLab job verbatim:

```yaml
unit-test:
  image: python:3.12-slim
  script:
    - python -m pip install -e ".[dev]"
    - pytest -q
```

- [ ] **Step 7: Implement the multi-stage mock-only Docker contract**

Use a builder stage that copies only package inputs and runs `python -m build --wheel --no-isolation`. Use a runtime `python:3.12-slim` stage that copies and installs the wheel, sets `PYQUALITY_MODE=public_mock`, exposes 8000, and defines:

```dockerfile
CMD ["pyquality", "serve", "--host", "0.0.0.0", "--port", "8000", "--public-mock"]
```

The Dockerfile contains no API-key `ARG`/`ENV`, editable install, test invocation, host database copy, or provider-mode command. `.dockerignore` implements every exclusion asserted in Step 3 while leaving `pyproject.toml`, `src/`, and runtime bundled resources available to the builder.

- [ ] **Step 8: Rerun the unchanged distribution contract selectors to GREEN**

Run the Step 2 and Step 4 commands unchanged. Expected: all selected tests pass without warnings. Run the complete file:

```powershell
D:\Python\python.exe -m pytest tests/distribution/test_artifacts.py -v --basetemp "$env:TEMP\pyquality-task12-green-distribution"
```

- [ ] **Step 9: Build and inspect wheel/sdist outside the source tree**

Use a temporary output directory outside the repository:

```powershell
$task12Dist = Join-Path $env:TEMP 'pyquality-task12-dist'
D:\Python\python.exe -m build --no-isolation --outdir $task12Dist
Get-ChildItem -LiteralPath $task12Dist
```

Expected: exactly one `.whl` and one `.tar.gz`. Inspect both archives with bounded standard-library `zipfile`/`tarfile` code and assert required runtime files are present and prohibited files absent.

- [ ] **Step 10: Verify isolated wheel installation and deterministic CLI**

Create a temporary venv with `--system-site-packages`, install the newly built wheel with `--no-deps`, change working directory outside the repository, then run:

```text
python -c "import pyquality; print(pyquality.__file__)"
pyquality --help
pyquality demo --json
```

Assert the import path is inside the temporary venv rather than `src/`, help exits 0, and demo JSON reports the required deterministic guardrail/feedback/success evidence without network or credentials.

- [ ] **Step 11: Attempt Docker verification and record capability truthfully**

First run `docker version`. If client and daemon are available, run:

```text
docker build -t pyquality-harness:local .
docker image inspect pyquality-harness:local
```

Verify configured environment and command match the approved mock-only contract. If the executable or daemon is unavailable, record the exact command/error as an environment capability result; do not install Docker, weaken tests, claim a build, or block the remaining local verification.

- [ ] **Step 12: Run security, full-suite, and formatting gates**

```powershell
git grep -n -E 'sk-[A-Za-z0-9]{12,}|Bearer [A-Za-z0-9._-]{12,}' -- ':!tests/**' ':!docs/**'
D:\Python\python.exe -m pytest -q --basetemp "$env:TEMP\pyquality-task12-full"
D:\Python\python.exe -m ruff check src tests
git diff --check
```

Expected: secret scan has no matches; pytest exits 0 at 100%; Ruff and diff checks exit 0.

- [ ] **Step 13: Commit Task 1 and prepare task review evidence**

```powershell
git add README.md .github/workflows/ci.yml .gitlab-ci.yml Dockerfile .dockerignore pyproject.toml tests/distribution/test_artifacts.py
git commit -m "build: define course distribution contract"
```

Write this task's SDD report with literal RED/GREEN, archive, isolated-install, Docker-capability, secret-scan, full-suite, and self-review evidence. Generate a frozen review package from the recorded Task 1 base.

---

### Task 2: Synchronize Evidence-Backed Course Records

**Files:**
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `SPEC.md` only if an approved Task 11A/11B invariant is missing from the root specification
- Modify: `SPEC_PROCESS.md` only if an already-recorded approved brainstorming decision is missing
- Modify: `tests/distribution/test_artifacts.py`

**Interfaces:**
- Consumes: Git history through the reviewed Task 1 commit; approved Task 11, 11A, 11B specs/plans; Task 11/11A/11B reports already committed or referenced by commit history; Task 1 verification report.
- Produces: a current root task ledger and chronological evidence log containing only traceable commits, review verdicts, test counts, capability limits, and human approvals.

- [ ] **Step 1: Add root-evidence contract RED tests**

Extend `tests/distribution/test_artifacts.py` to parse the Markdown task ledger and assert rows exist for Tasks 11 and 12 with concrete status, agents, spec review, quality review, and hexadecimal commits. Assert `AGENT_LOG.md` contains chronological headings for Task 11 implementation/breaker, Task 11A remediation/breaker, Task 11B remediation/CLEAN, and Task 12 distribution work.

Include history-preservation assertions:

```python
assert "Task 11A" in agent_log and "breaker" in agent_log.lower()
assert "Task 11B" in agent_log and "CLEAN" in agent_log
assert "6de2411" in agent_log
assert "cad8e17" in agent_log
```

Do not require a hosted URL or remote pipeline reference.

- [ ] **Step 2: Run evidence tests and capture RED**

```powershell
D:\Python\python.exe -m pytest tests/distribution/test_artifacts.py -k "root_evidence or task_ledger or agent_log" -v --basetemp "$env:TEMP\pyquality-task12-red-evidence"
```

Expected: fail because the root ledger stops at Task 10 and `AGENT_LOG.md` lacks Task 11/11A/11B/12 entries.

- [ ] **Step 3: Establish the exact evidence inventory from Git**

Use read-only commands before editing:

```powershell
git log --oneline --decorate --all
git show --stat --oneline 9f44513
git show --stat --oneline 6de2411
git show --stat --oneline cad8e17
git show --stat --oneline HEAD
```

Cross-check approved Task 11A/11B specs, plans, committed progress/report files, and final review verdicts. Record unavailable agent identities as unavailable rather than guessing them.

- [ ] **Step 4: Update PLAN.md task ledger without rewriting history**

Add rows for:

- Task 11: implementation completed but five-round review breaker reached;
- Task 11A: separate remediation reached its five-round breaker with the POSIX directory-entry durability defect;
- Task 11B: remediation CLEAN after task and final review, ending at `cad8e17`;
- Task 12: current implementation commits and review status available at the time of this edit.

Use actual implementing-agent identifiers only when present in retained evidence. Keep Task 11A blocked history visible even though Task 11B closes its remaining defect.

- [ ] **Step 5: Append chronological AGENT_LOG.md evidence**

Append dated sections that name the approved specs/plans, actual implementation/fix commits, breaker outcomes, CLEAN verdicts, literal verification counts available in retained reports, Docker capability outcome, and human approvals. Separate implementation evidence from reviewer findings. Do not state that Task 12 is clean until its task review has actually returned clean; before review, record it as implemented and awaiting review.

- [ ] **Step 6: Synchronize SPEC.md/SPEC_PROCESS.md only if comparison proves a gap**

Compare root documents with approved Task 11A/11B specs. If a durable receipt invariant is missing, add the concise normative invariant to the audit/recovery section of `SPEC.md`. If the approved brainstorming choices are already preserved in dated design files and `SPEC_PROCESS.md` is scoped only to pre-implementation evidence, leave it unchanged and state that decision in the report.

Never copy implementation-plan checklists into `SPEC.md` or invent retrospective dialogue in `SPEC_PROCESS.md`.

- [ ] **Step 7: Run unchanged evidence selectors to GREEN**

Run the Step 2 command unchanged, then the complete distribution file. Expected: pass with Task 12 correctly represented as implemented/under review rather than falsely complete.

- [ ] **Step 8: Run final local delivery verification**

Repeat Task 1's wheel/sdist build, archive inspection, isolated wheel CLI/demo, secret scan, full pytest, Ruff, and diff checks against the final documentation tree. Re-attempt Docker only when the environment capability has changed; otherwise cite the exact previously recorded capability result without claiming success.

- [ ] **Step 9: Commit Task 2 and prepare review evidence**

```powershell
git add PLAN.md AGENT_LOG.md tests/distribution/test_artifacts.py
git add SPEC.md SPEC_PROCESS.md  # only if Step 6 changed them
git commit -m "docs: record Task 11 and delivery evidence"
```

Update this task's SDD report and ledger, generate a frozen cumulative Task 2 review package from its recorded base, and dispatch specification-compliance then code-quality review. Task 13 remains locked.
