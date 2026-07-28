# PyQuality Harness Task Ledger

| Task | Status | Implementing agent | Spec review | Quality review | Commit |
| --- | --- | --- | --- | --- | --- |
| 0 | Complete | `/root/task0_docs_coldstart`, `/root/task0_docs_coldstart/coldstart_validator` | Clean re-review | Documentation contract checks clean | `2fdb099`, `b5cdd29`, `efc73b3` |
| 1 | Complete | `/root/task1_domain_config` | Clean after fix round 3 | 47 passed; Ruff clean | `297d277`, `6df8353`, `a3908f9`, `920983e`, `a200b8b` |
| 2 | Complete | `/root/task2_storage_memory` | Clean after fix round 1 | 64 passed; Ruff clean; two deferred minors: repository close/context-manager support and directory-prefix/validator-scope selector tests | `73261de`, `a606267` |
| 3 | Complete | `/root/task3_policy` | Human ruling: SPEC §14.2 is binding for revalidation; clean after fix round 1 | 88 passed; 3 WinError-1314 symlink skips; Ruff clean; deferred Minor: threshold-boundary coverage | `7b570c2`, `422382f` |
| 4 | Complete | `/root/task4_tools`, `/root/task4_fix_round4` | Clean after fix round 4 | 113 passed; 5 skipped; Ruff clean; portable POSIX syscall contract passed locally, while the POSIX rename/symlink end-to-end test was unavailable on the Windows host | `b7a5d6c`, `ae7785d`, `c20a668`, `14becd2`, `6eea0e9` |
| 5 | Complete | Initial implementer identity unavailable after context compaction; `/root/task5_fix1` (fix rounds) | `/root/task5_review`: clean after fix round 2 | 140 passed; 5 skipped; Ruff and diff-check clean | `411f7ae`, `ba45a82`, `f5e8145` |
| 6–13 | Not started | — | — | — | — |

# PyQuality Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first Python coding-agent harness whose typed tools, governance, pytest/Ruff feedback loop, progress detection, persistence, and WebUI remain deterministically testable with a mock LLM.

**Architecture:** A framework-independent core owns the state machine and depends on narrow protocols for model calls, storage, process execution, credentials, and time. Typed actions pass through policy before effects; code changes trigger validators whose normalized findings drive bounded correction rounds. CLI and FastAPI/Jinja/HTMX are thin adapters over the same application service.

**Tech Stack:** Python 3.12, Pydantic 2, FastAPI, Jinja2, HTMX, SQLite, keyring, httpx, pytest, Ruff, build, Docker/OCI.

## Global Constraints

- Support Python 3.12 and Python repositories only.
- Do not import a high-level agent runner, tool router, governance hook, or memory framework.
- Expose only typed file/search/patch/quality/finish actions; never expose arbitrary shell.
- Use pytest and Ruff as the only first-version validators.
- Default to eight model rounds, two concurrent repositories, and a configurable concurrency range of one through four.
- Require approval for deletion, dependency or CI changes, more than 10 touched files, or more than 300 changed lines.
- Deny repository escape, sensitive-file access, network effects, Git push, publishing, privilege escalation, and destructive system actions.
- Store provider credentials through the operating-system credential store; never persist or log secret values.
- Keep all core tests deterministic, offline, and runnable with a scripted mock LLM.
- A task succeeds only when full pytest and Ruff both pass.
- The public deployment uses only bundled repositories and mock LLM scenarios and accepts no API key or arbitrary path.
- Follow TDD for every behavior: observe the failing test before writing minimal implementation.

## File and Responsibility Map

```text
pyproject.toml                         package metadata, dependencies, CLI, pytest/Ruff configuration
src/pyquality/domain/models.py        actions, findings, task states, approvals, immutable result types
src/pyquality/config.py               secure defaults and typed TOML merge/validation
src/pyquality/storage/sqlite.py       schema, transactions, repositories, leases, resume state
src/pyquality/memory.py               deterministic decision/finding/iteration selection
src/pyquality/policy.py               path confinement, sensitive paths, risk classification
src/pyquality/tools.py                typed filesystem/search/patch effects behind process protocol
src/pyquality/validators.py           pytest/Ruff execution and raw-result capture
src/pyquality/parsers.py              raw pytest/Ruff output to normalized findings
src/pyquality/feedback.py             grouping, priority, evidence budgets, fingerprints, progress
src/pyquality/llm.py                  LLM protocol, scripted mock, OpenAI-compatible single-call client
src/pyquality/context.py              bounded model messages and file excerpt selection
src/pyquality/loop.py                 agent state machine, approvals, retries, terminal decisions
src/pyquality/security.py             credential service and centralized recursive redaction
src/pyquality/service.py              repository leases, background task orchestration, audit export
src/pyquality/cli.py                  run/serve/demo/credential commands
src/pyquality/web/app.py              FastAPI composition, CSRF/session handling, public-demo restrictions
src/pyquality/web/templates/*.html    server-rendered pages
src/pyquality/demo.py                 bundled deterministic mechanism demonstration
tests/                                unit, component, loop, web, security, and demo tests
examples/broken_calculator/           isolated reproducible repair fixture
.github/workflows/ci.yml              push/PR test, lint, package, and image build
.gitlab-ci.yml                        course-mandated unit-test job
Dockerfile                            mock-only public demonstration image
README.md                             required installation, use, distribution, key, and safety documentation
SPEC.md                               reviewed course design deliverable
PLAN.md                               tracked course plan/index and task commit ledger
SPEC_PROCESS.md                       brainstorming and cold-start evidence
AGENT_LOG.md                          chronological skill/task/intervention evidence
```

---

### Task 0: Materialize Course Spec/Plan and Run Pre-implementation Cold Start

**Files:**
- Create: `SPEC.md`
- Create: `PLAN.md`
- Create: `SPEC_PROCESS.md`
- Create: `AGENT_LOG.md`
- Modify: `docs/superpowers/specs/2026-07-28-pyquality-harness-design.md`
- Modify: `docs/superpowers/plans/2026-07-28-pyquality-harness.md`

**Interfaces:**
- Consumes: the approved design at `docs/superpowers/specs/2026-07-28-pyquality-harness-design.md` and this plan.
- Produces: self-contained root course deliverables, cold-start ambiguity evidence, and corrected contracts that every implementation task consumes.

- [ ] **Step 1: Materialize self-contained root deliverables**

Copy the complete approved design into `SPEC.md` and the complete reviewed implementation plan into `PLAN.md`; neither root file may be a link-only wrapper. Add a task ledger to `PLAN.md` with columns `Task`, `Status`, `Implementing agent`, `Spec review`, `Quality review`, and `Commit`. Create `SPEC_PROCESS.md` containing the actual brainstorming alternatives, the seven approved design sections, at least three key dialogue iterations, and adopted/rejected suggestions. Create `AGENT_LOG.md` with dated entries for brainstorming, writing-plans, and commit `de51d59`; do not record future events.

- [ ] **Step 2: Commit the planning baseline before implementation**

```bash
git add SPEC.md PLAN.md SPEC_PROCESS.md AGENT_LOG.md docs/superpowers
git commit -m "docs: materialize reviewed spec and implementation plan"
```

- [ ] **Step 3: Run the required cold-start validation without conversation history**

Start a fresh agent of a different type and provide only `SPEC.md` and `PLAN.md`. Ask it to dry-run the reasoning for Task 1 and one risk-heavy task without writing implementation code, and to stop at uncertainty rather than guess. Record every question, divergent interpretation, and expected file/interface mismatch in `SPEC_PROCESS.md`.

- [ ] **Step 4: Resolve every genuine ambiguity and verify document contracts**

For each finding, make the narrowest explicit correction in both the canonical docs file and its root counterpart. Run:

`$bad = @('T'+'BD', 'T'+'ODO', 'FIX'+'ME', 'implement '+'later', 'fill in', 'Similar to '+'Task'); Get-ChildItem SPEC.md,PLAN.md,docs/superpowers -File -Recurse | Select-String -Pattern $bad`

Expected: no matches. Then compare every `Consumes` symbol against an earlier `Produces` block and correct any naming or ordering mismatch.

- [ ] **Step 5: Commit cold-start corrections and evidence**

```bash
git add SPEC.md PLAN.md SPEC_PROCESS.md AGENT_LOG.md docs/superpowers
git commit -m "docs: incorporate cold-start specification feedback"
```

### Task 1: Package Foundation, Domain Types, and Secure Configuration

**Files:**
- Create: `pyproject.toml`
- Create: `src/pyquality/__init__.py`
- Create: `src/pyquality/domain/__init__.py`
- Create: `src/pyquality/domain/models.py`
- Create: `src/pyquality/config.py`
- Create: `tests/unit/test_models.py`
- Create: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: no application interfaces.
- Produces: `Action`, `Finding`, `QualityReport`, `TaskStatus`, `TaskResult`, `PolicyOutcome`, `ToolResult`, `ApprovalDecision`, `AuditEvent`, `Settings`, `ConfigError`, and `load_settings(repo_root: Path, user_file: Path | None) -> Settings`.

- [ ] **Step 1: Create package metadata and install the editable development environment**

```toml
[build-system]
requires = ["hatchling>=1.25,<2"]
build-backend = "hatchling.build"

[project]
name = "pyquality-harness"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "fastapi>=0.115,<1", "httpx>=0.27,<1", "jinja2>=3.1,<4",
  "keyring>=25,<26", "pydantic>=2.9,<3", "python-multipart>=0.0.12,<1",
  "uvicorn>=0.30,<1",
]

[project.optional-dependencies]
dev = ["build>=1.2,<2", "pytest>=8.3,<9", "ruff>=0.8,<1"]

[project.scripts]
pyquality = "pyquality.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"

[tool.ruff]
target-version = "py312"
line-length = 100
```

Run: `python -m pip install -e ".[dev]"`
Expected: package installs and `python -c "import pyquality"` exits 0.

- [ ] **Step 2: Write failing domain-model tests**

```python
from pyquality.domain.models import Action, Finding, TaskStatus

def test_action_rejects_unknown_kind() -> None:
    import pytest
    with pytest.raises(ValueError):
        Action.model_validate({"kind": "shell", "command": "whoami"})

def test_finding_has_stable_required_shape() -> None:
    item = Finding(source="pytest", category="assertion", severity="error",
                   path="tests/test_math.py", line=8, summary="1 != 2",
                   evidence="E assert 1 == 2", group_key="assert:test_math:8")
    assert item.category == "assertion"
    assert TaskStatus.SUCCEEDED.value == "succeeded"
```

Run: `pytest tests/unit/test_models.py -v`
Expected: FAIL because `pyquality.domain.models` does not exist.

- [ ] **Step 3: Implement the minimal typed domain model**

```python
class TaskStatus(StrEnum):
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    STALLED = "stalled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    BLOCKED = "blocked"
    FAILED = "failed"

class Action(BaseModel):
    kind: Literal["read_file", "search_text", "list_files", "apply_patch", "run_quality", "finish"]
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=2_000)

class Finding(BaseModel):
    source: Literal["pytest", "ruff", "harness"]
    category: Literal["syntax", "import_collection", "assertion", "runtime", "ruff",
                      "timeout", "missing_tool_dependency", "infrastructure"]
    severity: Literal["error", "warning"]
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    summary: str
    evidence: str
    group_key: str
```

Also define the remaining produced types as Pydantic models with explicit fields and no `Any` at public boundaries.

- [ ] **Step 4: Write failing configuration tests, then implement safe merging**

```python
def test_repository_config_cannot_widen_security(tmp_path: Path) -> None:
    (tmp_path / "pyquality.toml").write_text('[security]\nallow_shell=true\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown field"):
        load_settings(tmp_path, None)

def test_defaults_are_exact(tmp_path: Path) -> None:
    settings = load_settings(tmp_path, None)
    assert (settings.round_limit, settings.global_concurrency) == (8, 2)
    assert settings.global_concurrency <= 4
```

Run before implementation: `pytest tests/unit/test_config.py -v`
Expected: FAIL because configuration symbols do not exist.

Implement `Settings` with `extra="forbid"`, round limit, 1–4 concurrency, timeouts, safe pytest/Ruff argument lists, exclusions, and byte budgets. The UTF-8 byte/count defaults are `max_rationale_bytes=4_096`, `max_finding_summary_bytes=1_024`, `max_finding_evidence_bytes=4_096`, `max_group_key_bytes=512`, `max_action_arguments_bytes=65_536`, `max_tool_output_bytes=65_536`, `max_tool_metadata_bytes=16_384`, `max_config_pattern_bytes=1_024`, `max_config_patterns=128`, `source_excerpt_bytes=8_192`, and `feedback_total_bytes=32_768`; repository settings may only lower these caps. Parse only `pyquality.toml` as repository configuration; merge defaults → optional user file → repository file.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_models.py tests/unit/test_config.py -v && ruff check src tests`
Expected: all tests PASS and Ruff exits 0.

```bash
git add pyproject.toml src/pyquality tests/unit/test_models.py tests/unit/test_config.py
git commit -m "feat: establish typed domain and secure configuration"
```

### Task 2: SQLite State, Repository Leases, and Selective Memory

**Files:**
- Create: `src/pyquality/storage/__init__.py`
- Create: `src/pyquality/storage/sqlite.py`
- Create: `src/pyquality/memory.py`
- Create: `tests/unit/test_storage.py`
- Create: `tests/unit/test_memory.py`

**Interfaces:**
- Consumes: domain types from Task 1.
- Produces: `SQLiteTaskRepository(db_path: Path)`, `create_task`, `append_iteration`, `set_status`, `record_approval`, `acquire_project_lease`, `release_project_lease`, `resume_snapshot`, and `MemorySelector.select(snapshot, current_paths, max_iterations=2) -> MemoryContext`.
- `TaskRecord(id: str, project_id: str, request: str, status: TaskStatus, round_limit: int, deadline: datetime | None, result: TaskResult | None)`; `IterationRecord(id: str, task_id: str, sequence: int, context_digest: str, action_json: str | None, policy_outcome: PolicyOutcome | None, tool_result_digest: str | None, fingerprint: str | None, relevant_digest: str | None, created_at: datetime)`; `FindingRecord(id: str, iteration_id: str, finding: Finding, created_at: datetime, resolved_at: datetime | None)`; `ApprovalRecord(id: str, task_id: str, iteration_id: str, action_json: str, action_digest: str, repository_snapshot_digest: str, decision: ApprovalDecision | None, execution_state: Literal["pending", "intent_recorded", "completed"], decided_at: datetime | None, executed_at: datetime | None)`; and `DecisionRecord(id, project_id, scope_type, scope_value, content, source, created_at, updated_at)` are immutable Pydantic records defined in `storage/sqlite.py`.
- `RecoverySnapshot(task, iterations, findings, decisions, pending_approval, executable_approval)` returns `FindingRecord` values and only an approved, not-completed `executable_approval`. `create_task(canonical_path, request, round_limit, deadline=None)`, `append_iteration(task_id, *, sequence, context_digest, action_json=None, policy_outcome=None, tool_result_digest=None, fingerprint=None, relevant_digest=None, findings=())`, `mark_findings_resolved(finding_ids, resolved_at=None) -> int`, and `set_status(task_id, expected, new, result=None) -> bool` provide persistence and compare-and-set transitions. `record_approval(task_id, iteration_id, action_json, action_digest, repository_snapshot_digest)`, `pending_approval(task_id)`, `decide_approval(approval_id, decision)`, `mark_execution_intent(approval_id)`, `mark_execution_completed(approval_id)`, `add_decision(...)`, lease methods, and `resume_snapshot(task_id)` provide the recovery and memory data surface. Illegal/missing approval transitions and duplicate iteration sequences raise `StorageStateError`; a CAS mismatch returns `False`.

- [ ] **Step 1: Write failing persistence and lease tests**

```python
def test_second_active_task_cannot_lease_same_project(repo: SQLiteTaskRepository) -> None:
    first = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    second = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    assert repo.acquire_project_lease(first.id) is True
    assert repo.acquire_project_lease(second.id) is False

def test_resume_does_not_return_unapproved_action_as_executable(repo: SQLiteTaskRepository) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    repo.record_approval(task.id, action_json='{"kind":"apply_patch"}', decision=None)
    assert repo.resume_snapshot(task.id).executable_approval is None
```

Run: `pytest tests/unit/test_storage.py -v`
Expected: FAIL because storage is absent.

- [ ] **Step 2: Implement schema and transactional repository methods**

Use SQLite foreign keys, WAL mode, unique `(task_id, sequence)`, and a unique active lease per canonical project path. Persist `Project`, `Task`, `Iteration`, `Finding`, `Approval`, `Decision`, and `AuditEvent`; store JSON using sorted keys. Commit each state transition in one transaction.

Run: `pytest tests/unit/test_storage.py -v`
Expected: PASS.

- [ ] **Step 3: Write failing selective-memory tests**

```python
def test_memory_selects_two_recent_iterations_and_matching_decisions(snapshot) -> None:
    context = MemorySelector().select(snapshot, {"src/math.py"}, max_iterations=2)
    assert [item.sequence for item in context.iterations] == [3, 4]
    assert [d.content for d in context.decisions] == ["Use Decimal in src/math.py"]
    assert "unrelated README wording" not in context.model_dump_json()
```

Run: `pytest tests/unit/test_memory.py -v`
Expected: FAIL because `MemorySelector` does not exist.

- [ ] **Step 4: Implement deterministic memory selection**

Select unresolved error findings first, then warnings; match decisions by exact path prefix or validator scope; include only the latest two iterations; sort ties by creation time and ID. Return typed `MemoryContext`, never raw terminal output.

Run: `pytest tests/unit/test_memory.py -v`
Expected: PASS.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_storage.py tests/unit/test_memory.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/storage src/pyquality/memory.py tests/unit/test_storage.py tests/unit/test_memory.py
git commit -m "feat: persist task state and select bounded memory"
```

### Task 3: Path Confinement and Governance Policy

**Files:**
- Create: `src/pyquality/policy.py`
- Create: `tests/unit/test_policy.py`

**Interfaces:**
- Consumes: `Action`, `PolicyOutcome`.
- Produces: `PolicyEngine(repo_root: Path, sensitive_patterns: tuple[str, ...])`, `evaluate(action: Action) -> PolicyDecision`, and `revalidate(decision: PolicyDecision, action: Action, current_snapshot_digest: str) -> PolicyDecision`. `PolicyDecision` carries the canonical repository snapshot digest saved at evaluation.

- [ ] **Step 1: Write the path-escape and sensitive-file failing tests**

```python
@pytest.mark.parametrize("path", ["../outside.txt", ".env", "id_rsa", ".git/config"])
def test_denies_escape_and_sensitive_reads(tmp_path: Path, path: str) -> None:
    action = Action(kind="read_file", arguments={"path": path}, rationale="inspect")
    decision = PolicyEngine(tmp_path).evaluate(action)
    assert decision.outcome is PolicyOutcome.DENY

def test_symlink_escape_is_denied(tmp_path: Path, tmp_path_factory) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    action = Action(kind="read_file", arguments={"path": "link/secret"}, rationale="inspect")
    assert PolicyEngine(tmp_path).evaluate(action).outcome is PolicyOutcome.DENY
```

Run: `pytest tests/unit/test_policy.py -v`
Expected: FAIL because policy is absent.

- [ ] **Step 2: Implement canonicalization and deny rules**

Resolve paths strictly where possible, resolve parents for new patch paths, reject any canonical target not contained by the canonical root, and deny `.env`, `.git`, private-key patterns, credential directories, and action kinds outside the `Action` union.

Run: `pytest tests/unit/test_policy.py -v`
Expected: the deny tests PASS.

- [ ] **Step 3: Add failing approval-threshold tests**

```python
def test_broad_patch_requires_approval(tmp_path: Path) -> None:
    patch = make_patch(files=11, added_lines_each=1)
    action = Action(kind="apply_patch", arguments={"patch": patch}, rationale="wide repair")
    assert PolicyEngine(tmp_path).evaluate(action).outcome is PolicyOutcome.REQUIRE_APPROVAL

def test_dependency_change_requires_approval(tmp_path: Path) -> None:
    action = Action(kind="apply_patch", arguments={"patch": patch_for("pyproject.toml")}, rationale="add dep")
    assert PolicyEngine(tmp_path).evaluate(action).outcome is PolicyOutcome.REQUIRE_APPROVAL
```

Run: `pytest tests/unit/test_policy.py -v`
Expected: FAIL until thresholds and protected paths are implemented.

- [ ] **Step 4: Implement ALLOW/REQUIRE_APPROVAL/DENY and revalidation**

Count additions plus deletions and unique touched files before applying. Require approval above 10 files or 300 lines, for deletion, and for dependency/CI paths. Bind decisions to a SHA-256 digest of normalized action JSON and a repository snapshot digest; `revalidate` denies an action-digest mismatch or snapshot drift, then recomputes policy against the supplied action and current filesystem.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_policy.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/policy.py tests/unit/test_policy.py
git commit -m "feat: enforce repository governance policy"
```

### Task 4: Typed Tool Dispatcher and Bounded Effects

**Files:**
- Create: `src/pyquality/tools.py`
- Create: `tests/unit/test_tools.py`
- Create: `tests/component/test_patch_tools.py`

**Interfaces:**
- Consumes: allowed `Action`, `ToolResult`, canonical root.
- Produces: `ToolDispatcher.dispatch(action: Action, decision: PolicyDecision, current_snapshot_digest: str) -> ToolResult`, `ProcessRunner.run(argv: list[str], cwd: Path, timeout_s: int, output_limit: int) -> ProcessResult`, and `SubprocessRunner`. `ToolDispatcher(repo_root, policy, process_runner, settings)` revalidates the supplied action-bound decision immediately before every effect and performs work only when that revalidation resolves `ALLOW`; `REQUIRE_APPROVAL` and `DENY` return a bounded no-effect `policy_denied` result.

- [ ] **Step 1: Write failing bounded read/search/list tests**

```python
def test_read_is_bounded_and_marks_truncation(dispatcher, repo) -> None:
    (repo / "large.py").write_text("x=1\n" * 1000, encoding="utf-8")
    result = dispatcher.dispatch(Action(kind="read_file", arguments={"path": "large.py"}, rationale="read"))
    assert result.truncated is True
    assert len(result.output.encode()) <= dispatcher.output_limit

def test_list_ignores_git_and_venv(dispatcher, repo) -> None:
    assert ".git/config" not in dispatcher.dispatch(list_action()).output
    assert ".venv/lib.py" not in dispatcher.dispatch(list_action()).output
```

Run: `pytest tests/unit/test_tools.py -v`
Expected: FAIL because dispatcher is absent.

- [ ] **Step 2: Implement read, search, and list without shell interpolation**

Use `Path.read_text`, deterministic `Path.walk` ordering, literal UTF-8 substring search with a match-count limit, explicit exclusions (including every policy-sensitive filename), and UTF-8 error reporting. The first version deliberately does not support regex search. Require callers to supply only policy-approved actions.

- [ ] **Step 3: Write failing contextual patch tests**

```python
def test_patch_rejects_missing_context(dispatcher, repo) -> None:
    result = dispatcher.dispatch(apply_patch_action("@@ -1 +1 @@\n-nope\n+fixed\n"))
    assert result.ok is False
    assert result.code == "patch_context_mismatch"

def test_patch_is_atomic(dispatcher, repo) -> None:
    before = (repo / "a.py").read_bytes()
    result = dispatcher.dispatch(apply_patch_action(invalid_second_hunk_patch()))
    assert result.ok is False
    assert (repo / "a.py").read_bytes() == before
```

Run: `pytest tests/component/test_patch_tools.py -v`
Expected: FAIL until patching exists.

- [ ] **Step 4: Implement atomic unified-patch application and process protocol**

Parse unified patches in Python, verify every old hunk against an in-memory file snapshot, write changed files only after all hunks validate, and use replace-through-temporary-file in the same directory. The first version deliberately rejects `\\ No newline at end of file` markers and targets without a final newline while preserving LF or CRLF for valid targets. Implement `SubprocessRunner` with `shell=False`, fixed cwd, timeout, combined byte cap, and explicit timeout result.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_tools.py tests/component/test_patch_tools.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/tools.py tests/unit/test_tools.py tests/component/test_patch_tools.py
git commit -m "feat: dispatch bounded typed repository tools"
```

### Task 5: Pytest/Ruff Validators and Finding Parsers

**Files:**
- Create: `src/pyquality/validators.py`
- Create: `src/pyquality/parsers.py`
- Create: `tests/fixtures/validator_outputs/*.txt`
- Create: `tests/unit/test_parsers.py`
- Create: `tests/component/test_validators.py`

**Interfaces:**
- Consumes: `ProcessRunner`, `Settings`.
- Produces: `RawValidationResult`, `PytestValidator.run(changed_paths)`, `RuffValidator.run()`, `QualityPipeline.run(changed_paths: set[Path]) -> QualityReport`, and `parse_pytest`/`parse_ruff -> tuple[Finding, ...]`.

- [ ] **Step 1: Add representative fixtures and failing parser tests**

```python
@pytest.mark.parametrize(("fixture", "category"), [
    ("pytest_assertion.txt", "assertion"),
    ("pytest_import.txt", "import_collection"),
    ("pytest_syntax.txt", "syntax"),
    ("pytest_runtime.txt", "runtime"),
])
def test_pytest_categories(load_fixture, fixture, category) -> None:
    findings = parse_pytest(load_fixture(fixture), exit_code=1)
    assert findings[0].category == category

def test_ruff_json_maps_location(load_fixture) -> None:
    finding = parse_ruff(load_fixture("ruff.json"), exit_code=1)[0]
    assert (finding.category, finding.path, finding.line) == ("ruff", "src/a.py", 3)
```

Run: `pytest tests/unit/test_parsers.py -v`
Expected: FAIL because parsers do not exist.

- [ ] **Step 2: Implement parsers and unknown-infrastructure fallback**

Use Ruff JSON output. Parse pytest sections, exception headers, file/line locations, and exit codes; normalize path separators. Missing executable maps to `missing_tool_dependency`; timeout maps to `timeout`; unmatched nonzero output maps to `infrastructure`. Preserve compact raw evidence only.

- [ ] **Step 3: Write failing validator-order and targeted-test tests**

```python
def test_changed_test_file_runs_target_then_full_then_ruff(recording_runner, settings) -> None:
    pipeline = QualityPipeline(recording_runner, settings)
    pipeline.run({Path("tests/test_math.py")})
    assert [call.argv for call in recording_runner.calls] == [
        ["python", "-m", "pytest", "tests/test_math.py"],
        ["python", "-m", "pytest"],
        ["python", "-m", "ruff", "check", "--output-format", "json", "."],
    ]
```

Run: `pytest tests/component/test_validators.py -v`
Expected: FAIL because the pipeline is absent.

- [ ] **Step 4: Implement pipeline short-circuit and success rules**

Run a changed test file only when its normalized path matches `tests/test_*.py` or `test_*.py`; then always run the full suite unless preflight is blocked; then Ruff. Mark the report successful only when full pytest and Ruff exit 0. Include durations and raw-result digests.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_parsers.py tests/component/test_validators.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/validators.py src/pyquality/parsers.py tests/fixtures tests/unit/test_parsers.py tests/component/test_validators.py
git commit -m "feat: normalize pytest and Ruff quality signals"
```

### Task 6: Feedback Compression, Fingerprints, and Stop Decisions

**Files:**
- Create: `src/pyquality/feedback.py`
- Create: `tests/unit/test_feedback.py`
- Create: `tests/unit/test_progress.py`

**Interfaces:**
- Consumes: `Finding`, `QualityReport`, iteration history.
- Produces: `FeedbackComposer.compose(findings, total_bytes, per_item_bytes) -> FeedbackPacket`, `failure_fingerprint(findings) -> str`, and `ProgressTracker.decide(history, round_limit, deadline, now) -> TaskStatus | None`.

- [ ] **Step 1: Write failing priority, grouping, and truncation tests**

```python
def test_feedback_orders_root_causes_and_reports_truncation() -> None:
    packet = FeedbackComposer().compose(mixed_findings(), total_bytes=300, per_item_bytes=120)
    assert [f.category for f in packet.findings[:2]] == ["syntax", "assertion"]
    assert packet.omitted_count > 0
    assert packet.truncated is True

def test_duplicate_root_causes_are_grouped() -> None:
    packet = FeedbackComposer().compose(duplicate_import_failures(), 2_000, 500)
    assert len(packet.findings) == 1
    assert packet.findings[0].occurrences == 3
```

Run: `pytest tests/unit/test_feedback.py -v`
Expected: FAIL because feedback code is absent.

- [ ] **Step 2: Implement deterministic feedback composition**

Use priority `infrastructure/timeout/missing → syntax/import_collection → assertion/runtime → ruff`; group by `group_key`; sort ties by normalized path, line, and summary; truncate UTF-8 safely; state omitted count and byte budget in the packet.

- [ ] **Step 3: Write failing fingerprint and stopping tests**

```python
def test_fingerprint_ignores_temp_paths_and_timings() -> None:
    assert failure_fingerprint(findings("C:/Temp/a", "0.21s")) == failure_fingerprint(findings("D:/tmp/b", "1.90s"))

def test_same_failure_twice_without_relevant_change_stalls() -> None:
    history = [iteration("abc", relevant_digest="one"), iteration("abc", relevant_digest="one")]
    assert ProgressTracker().decide(history, 8, future(), now()) is TaskStatus.STALLED

def test_unrelated_change_does_not_count_as_progress() -> None:
    history = [iteration("abc", relevant_digest="one", all_digest="x"),
               iteration("abc", relevant_digest="one", all_digest="y")]
    assert ProgressTracker().decide(history, 8, future(), now()) is TaskStatus.STALLED
```

Run: `pytest tests/unit/test_progress.py -v`
Expected: FAIL until progress tracking exists.

- [ ] **Step 4: Implement normalization and all stopping branches**

Fingerprint sorted `(category, normalized relative path, line, group_key)` tuples using SHA-256. Decide `SUCCEEDED` from report success first, then `BLOCKED`, `STALLED`, `BUDGET_EXHAUSTED`, and `FAILED` inputs. Inject time through a caller-supplied `now` value.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_feedback.py tests/unit/test_progress.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/feedback.py tests/unit/test_feedback.py tests/unit/test_progress.py
git commit -m "feat: compose bounded feedback and detect progress"
```

### Task 7: LLM Boundary, Action Parsing, and Context Builder

**Files:**
- Create: `src/pyquality/llm.py`
- Create: `src/pyquality/context.py`
- Create: `tests/unit/test_llm.py`
- Create: `tests/unit/test_context.py`

**Interfaces:**
- Consumes: `Action`, `MemoryContext`, `FeedbackPacket`, credential callable.
- Produces: `Message`, `LLMClient.complete(messages: tuple[Message, ...]) -> str`, `ScriptedLLM`, `OpenAICompatibleLLM`, `ActionFormatError`, `ActionParser.parse(raw: str) -> Action`, and `ContextBuilder.build(...) -> tuple[Message, ...]`.

- [ ] **Step 1: Write failing scripted-client and parser tests**

```python
def test_scripted_llm_records_feedback_context() -> None:
    llm = ScriptedLLM(['{"kind":"finish","arguments":{},"rationale":"done"}'])
    assert "finish" in llm.complete((Message(role="user", content="failure: assertion"),))
    assert "failure: assertion" in llm.calls[0][0].content

def test_action_parser_rejects_shell() -> None:
    with pytest.raises(ActionFormatError):
        ActionParser().parse('{"kind":"shell","arguments":{"command":"ls"},"rationale":"x"}')
```

Run: `pytest tests/unit/test_llm.py -v`
Expected: FAIL because LLM boundary is absent.

- [ ] **Step 2: Implement mock, strict parser, and single-call HTTP adapter**

`ScriptedLLM` pops one response and raises a typed exhaustion error. `ActionParser` accepts exactly one JSON object and validates `Action`. `OpenAICompatibleLLM` uses `httpx.Client.post` for one response, obtains the key through `Callable[[], str]` immediately before the call, sets timeouts, and maps HTTP/provider errors without logging request headers or bodies.

- [ ] **Step 3: Write failing bounded-context tests**

```python
def test_context_contains_task_two_iterations_feedback_and_relevant_excerpt() -> None:
    messages = ContextBuilder(source_bytes=1_000, total_bytes=4_000).build(context_fixture())
    joined = "\n".join(m.content for m in messages)
    assert "fix decimal rounding" in joined
    assert "iteration 3" not in joined
    assert "iteration 4" in joined and "iteration 5" in joined
    assert "src/money.py" in joined
    assert "README-only decision" not in joined
```

Run: `pytest tests/unit/test_context.py -v`
Expected: FAIL until context builder exists.

- [ ] **Step 4: Implement explicit context sections and byte budgets**

Build messages with stable headings for task, allowed action schema, decisions, recent actions, relevant source, and structured feedback. Never include raw terminal output or secret-bearing settings. Truncate source by UTF-8 bytes and include a visible truncation marker.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_llm.py tests/unit/test_context.py -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/llm.py src/pyquality/context.py tests/unit/test_llm.py tests/unit/test_context.py
git commit -m "feat: add injectable LLM boundary and bounded context"
```

### Task 8: Agent Loop, Approval Pause/Resume, and Recovery

**Files:**
- Create: `src/pyquality/loop.py`
- Create: `tests/loop/test_agent_loop.py`
- Create: `tests/loop/test_approval_resume.py`

**Interfaces:**
- Consumes: all core protocols from Tasks 2–7.
- Produces: `AgentLoop.run(task_id: str) -> TaskResult`, `AgentLoop.resume(task_id: str) -> TaskResult`, and `AgentLoop.decide_approval(approval_id: str, decision: ApprovalDecision) -> None`.

- [ ] **Step 1: Write failing feedback-driven correction loop test**

```python
def test_failed_patch_feedback_changes_next_action(loop_fixture) -> None:
    llm = ScriptedLLM([bad_patch_json(), corrected_patch_json(), finish_json()])
    result = loop_fixture(llm=llm).run("task-1")
    assert result.status is TaskStatus.SUCCEEDED
    assert "assertion" in llm.calls[1][-1].content
    assert bad_patch_json() != corrected_patch_json()
    assert result.iterations == 3
```

Run: `pytest tests/loop/test_agent_loop.py -v`
Expected: FAIL because the loop is absent.

- [ ] **Step 2: Implement the state machine and two format-repair attempts**

Persist before and after model calls, policy decisions, tool effects, and validator reports. Route code changes to quality checks. Treat `finish` as a request to verify, not success. On invalid output, append a schema-only repair message and allow exactly two repair attempts before `FAILED`.

- [ ] **Step 3: Write failing approval and replay tests**

```python
def test_approval_pauses_and_executes_once(loop_fixture) -> None:
    loop, spy = loop_fixture(action=dependency_patch(), dispatcher_spy=True)
    assert loop.run("task-1").status is TaskStatus.WAITING_APPROVAL
    approval = loop.pending_approval("task-1")
    loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    loop.resume("task-1")
    loop.resume("task-1")
    assert spy.dispatch_count(dependency_patch()) == 1

def test_rejected_action_becomes_feedback(loop_fixture) -> None:
    loop, llm = loop_fixture(action=dependency_patch(), recording_llm=True)
    loop.run("task-1")
    loop.decide_approval(loop.pending_approval("task-1").id, ApprovalDecision.REJECT)
    loop.resume("task-1")
    assert "rejected by user" in llm.calls[-1][-1].content
```

Run: `pytest tests/loop/test_approval_resume.py -v`
Expected: FAIL until approval transitions exist.

- [ ] **Step 4: Implement action-bound approval, revalidation, resume, and all stop states**

Store the normalized action digest; approve or reject once; revalidate before dispatch; mark execution transactionally; resume from the last completed transition. Integrate `ProgressTracker` and ensure no model call occurs after a terminal decision.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/loop -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/loop.py tests/loop
git commit -m "feat: orchestrate bounded agent correction loop"
```

### Task 9: Credentials, Redaction, and Audit Logging

**Files:**
- Create: `src/pyquality/security.py`
- Create: `tests/security/test_credentials.py`
- Create: `tests/security/test_redaction.py`

**Interfaces:**
- Consumes: `keyring` backend and audit metadata.
- Produces: `CredentialService.set/status/get/clear`, `CredentialStatus`, `redact(value, secrets, sensitive_keys)`, and `AuditLogger.emit(event) -> None`.

- [ ] **Step 1: Write failing credential lifecycle tests with an in-memory backend**

```python
def test_credential_status_never_contains_secret(memory_keyring) -> None:
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("openai-compatible", "sk-secret")
    status = service.status("openai-compatible")
    assert status.present is True
    assert "sk-secret" not in repr(status)
    service.clear("openai-compatible")
    assert service.status("openai-compatible").present is False
```

Run: `pytest tests/security/test_credentials.py -v`
Expected: FAIL because security service is absent.

- [ ] **Step 2: Implement credential lifecycle and warned environment fallback**

Never expose a list or echo operation. `get` returns the key only to the provider callable. Detect unusable keyring backends; allow `PYQUALITY_API_KEY` only when explicitly selected and return a warning object stating process-visibility risk. Do not create `.env`.

- [ ] **Step 3: Write failing recursive redaction and audit tests**

```python
def test_redacts_nested_headers_urls_and_exception_text(tmp_path: Path) -> None:
    value = {"headers": {"Authorization": "Bearer sk-secret"},
             "url": "https://x.test/?api_key=sk-secret",
             "error": RuntimeError("failed with sk-secret")}
    clean = redact(value, secrets={"sk-secret"}, sensitive_keys={"authorization", "api_key"})
    assert "sk-secret" not in json.dumps(clean)

def test_audit_log_omits_source_and_prompt_by_default(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit.jsonl", secrets={"sk-secret"})
    logger.emit(AuditEvent(event_type="model", metadata={"prompt": "source body", "key": "sk-secret"}))
    text = (tmp_path / "audit.jsonl").read_text()
    assert "source body" not in text and "sk-secret" not in text
```

Run: `pytest tests/security/test_redaction.py -v`
Expected: FAIL until redaction and logging exist.

- [ ] **Step 4: Implement centralized recursive redaction and JSONL audit logger**

Redact secret values, authorization-like keys, URL query secrets, exception strings, prompt/model body keys, and bytes. Emit task ID, iteration, component, event type, duration, outcome, and approved metadata using one JSON object per line.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/security -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/security.py tests/security
git commit -m "feat: secure credentials and redact audit data"
```

### Task 10: Application Service, CLI, and Local WebUI

**Files:**
- Create: `src/pyquality/service.py`
- Create: `src/pyquality/cli.py`
- Create: `src/pyquality/web/__init__.py`
- Create: `src/pyquality/web/app.py`
- Create: `src/pyquality/web/templates/base.html`
- Create: `src/pyquality/web/templates/tasks_new.html`
- Create: `src/pyquality/web/templates/task_detail.html`
- Create: `src/pyquality/web/templates/approval.html`
- Create: `src/pyquality/web/templates/settings.html`
- Create: `tests/unit/test_service.py`
- Create: `tests/web/test_web.py`
- Create: `tests/web/test_public_mode.py`

**Interfaces:**
- Consumes: `AgentLoop`, storage, settings, credentials.
- Produces: `ProjectBusyError`, `PreflightError`, `HarnessService.create_task/start_task/get_task/approve/reject/export_audit`, `create_app(service, mode: Literal["local", "public_mock"]) -> FastAPI`, and `main()`.

- [ ] **Step 1: Write failing service concurrency and preflight tests**

```python
def test_service_rejects_second_task_for_same_repository(service, repo) -> None:
    service.create_task(repo, "first")
    with pytest.raises(ProjectBusyError):
        service.create_task(repo, "second")

def test_preflight_reports_missing_pytest(service, repo, fake_environment) -> None:
    fake_environment.missing("pytest")
    with pytest.raises(PreflightError, match="pytest"):
        service.create_task(repo, "fix")
```

Run: `pytest tests/unit/test_service.py -v`
Expected: FAIL because service is absent.

- [ ] **Step 2: Implement service, bounded background executor, and audit export**

Use a `ThreadPoolExecutor(max_workers=settings.global_concurrency)` in one application process. Acquire the repository lease before queueing, release it on terminal state, expose typed view models, and export only redacted structured events.

- [ ] **Step 3: Write failing WebUI security and workflow tests**

```python
def test_task_create_requires_csrf(client, repo) -> None:
    response = client.post("/tasks", data={"repo_path": str(repo), "request": "fix"})
    assert response.status_code == 403

def test_local_task_timeline_and_approval(client, csrf, seeded_service) -> None:
    created = client.post("/tasks", data={"repo_path": seeded_service.repo,
                                         "request": "fix", "csrf_token": csrf})
    page = client.get(created.headers["location"])
    assert "Remaining rounds" in page.text and "Waiting for approval" in page.text

def test_settings_never_renders_key(client, seeded_credentials) -> None:
    assert "sk-secret" not in client.get("/settings").text
```

Run: `pytest tests/web/test_web.py -v`
Expected: FAIL because WebUI is absent.

- [ ] **Step 4: Implement server-rendered pages, CSRF, CLI families, and public restrictions**

Bind local server to `127.0.0.1` by default. Use an HttpOnly, SameSite=Strict session cookie and per-session CSRF token for mutations. In `public_mock`, reject arbitrary path fields, credential endpoints, provider changes, and non-bundled scenarios. Implement `run`, `serve`, `demo`, and `credential set|status|clear` CLI families; use `getpass.getpass` for key input.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/unit/test_service.py tests/web -v && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/service.py src/pyquality/cli.py src/pyquality/web tests/unit/test_service.py tests/web
git commit -m "feat: expose harness through CLI and secure WebUI"
```

### Task 11: Deterministic Mechanism Demo and End-to-End Verification

**Files:**
- Create: `src/pyquality/demo.py`
- Create: `examples/broken_calculator/calculator.py`
- Create: `examples/broken_calculator/tests/test_calculator.py`
- Create: `tests/e2e/test_demo.py`
- Create: `tests/e2e/test_mechanism_contract.py`

**Interfaces:**
- Consumes: complete service and loop.
- Produces: `run_demo(work_dir: Path) -> DemoReport` and `pyquality demo --json`.

- [ ] **Step 1: Create the failing calculator fixture and failing demo contract**

```python
# examples/broken_calculator/calculator.py
def add(left: int, right: int) -> int:
    return left - right
```

```python
def test_demo_proves_guardrail_feedback_progress_and_success(tmp_path: Path) -> None:
    report = run_demo(tmp_path)
    assert report.denied_action.attempted is True
    assert report.denied_action.dispatch_count == 0
    assert report.first_failure_category == "assertion"
    assert report.model_saw_first_failure is True
    assert report.first_patch_digest != report.second_patch_digest
    assert report.first_fingerprint != report.second_fingerprint
    assert report.final_status is TaskStatus.SUCCEEDED
```

Run: `pytest tests/e2e/test_demo.py -v`
Expected: FAIL because demo is absent.

- [ ] **Step 2: Implement the fixed scripted scenario**

Script actions in this exact order: denied `read_file("../secret")`; bad contextual patch that changes the bug but still fails; corrected patch after receiving assertion feedback; `finish`. Copy the bundled fixture to a temporary work directory and record dispatch counts and model contexts.

- [ ] **Step 3: Add explicit mechanism-isolation assertions**

```python
def test_demo_uses_no_network_or_real_credentials(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: pytest.fail("network called"))
    monkeypatch.delenv("PYQUALITY_API_KEY", raising=False)
    assert run_demo(tmp_path).final_status is TaskStatus.SUCCEEDED
```

Run: `pytest tests/e2e/test_mechanism_contract.py -v`
Expected: PASS only after all demo dependencies are injected correctly.

- [ ] **Step 4: Run the demo twice and compare stable evidence**

Run: `pyquality demo --json`
Expected: exit 0; JSON contains denied dispatch count 0, assertion feedback, changed patch/fingerprint, and `succeeded`.

Run again: `pyquality demo --json`
Expected: the same ordered mechanism events and terminal status; timestamps and temporary paths may differ but normalized fingerprints match their corresponding stage.

- [ ] **Step 5: Verify and commit**

Run: `pytest tests/e2e -v && pytest -q && ruff check src tests`
Expected: PASS.

```bash
git add src/pyquality/demo.py examples tests/e2e
git commit -m "feat: add deterministic harness mechanism demo"
```

### Task 12: Course Deliverables, Packaging, CI, Docker, and Deployment Contract

**Files:**
- Modify: `SPEC.md`
- Modify: `PLAN.md`
- Modify: `SPEC_PROCESS.md`
- Modify: `AGENT_LOG.md`
- Create: `README.md`
- Create: `.github/workflows/ci.yml`
- Create: `.gitlab-ci.yml`
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `tests/distribution/test_artifacts.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: completed application and approved design/plan documents.
- Produces: installable wheel/sdist, mock-only OCI image, required course documents, and CI definitions.

- [ ] **Step 1: Write failing distribution-contract tests**

```python
def test_course_artifacts_and_ci_contract(repo_root: Path) -> None:
    for name in ["SPEC.md", "PLAN.md", "SPEC_PROCESS.md", "AGENT_LOG.md", "README.md", ".gitlab-ci.yml"]:
        assert (repo_root / name).is_file()
    gitlab = (repo_root / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert "unit-test:" in gitlab

def test_readme_required_sections(repo_root: Path) -> None:
    text = (repo_root / "README.md").read_text(encoding="utf-8")
    for heading in ["Installation", "Running", "Distribution", "Credential Security", "Project Structure", "Safety Boundaries", "Known Limitations"]:
        assert f"## {heading}" in text
```

Run: `pytest tests/distribution/test_artifacts.py -v`
Expected: FAIL because delivery artifacts are absent.

- [ ] **Step 2: Update the course documents with evidence already produced**

Synchronize approved specification and plan changes into the root files. Update the `PLAN.md` ledger with actual task status, implementing agent, review status, and commit hash. Add the completed pre-implementation cold-start results to `SPEC_PROCESS.md`. Append actual task evidence to `AGENT_LOG.md`; do not fabricate missing or future evidence.

- [ ] **Step 3: Write README, CI, and Docker definitions**

GitHub Actions must run on push and pull request with jobs for `pytest -q`, `ruff check src tests`, `python -m build`, and `docker build .`. `.gitlab-ci.yml` must contain:

```yaml
unit-test:
  image: python:3.12-slim
  script:
    - python -m pip install -e ".[dev]"
    - pytest -q
```

The Docker image installs the wheel, copies only bundled examples, sets `PYQUALITY_MODE=public_mock`, exposes 8000, and runs `pyquality serve --host 0.0.0.0 --port 8000 --public-mock`. README documents keyring setup, warned environment fallback, public/local mode separation, pytest code-execution risk, build/install/run commands, and Render-compatible container deployment.

- [ ] **Step 4: Verify packages, image, secret hygiene, and full suite**

Run: `python -m build`
Expected: one wheel and one sdist are created successfully.

Run: `docker build -t pyquality-harness:local .`
Expected: image builds and its default command starts public mock mode.

Run: `git grep -n -E 'sk-[A-Za-z0-9]{12,}|Bearer [A-Za-z0-9._-]{12,}' -- ':!tests/**' ':!docs/**'`
Expected: no output.

Run: `pytest -q && ruff check src tests`
Expected: PASS.

- [ ] **Step 5: Commit delivery artifacts**

```bash
git add SPEC.md PLAN.md SPEC_PROCESS.md AGENT_LOG.md README.md .github .gitlab-ci.yml Dockerfile .dockerignore pyproject.toml tests/distribution
git commit -m "docs: complete packaging and course delivery contract"
```

### Task 13: Final Release and Hosted Demonstration Evidence

**Files:**
- Modify: `SPEC.md`
- Modify: `PLAN.md`
- Modify: `SPEC_PROCESS.md`
- Modify: `AGENT_LOG.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: completed implementation, reviewed course documents, and passing local distribution checks.
- Produces: final CI/deployment evidence and the public mock URL.

- [ ] **Step 1: Audit pre-implementation cold-start evidence and task records**

Confirm `SPEC_PROCESS.md` contains the Task 0 agent type, supplied inputs, questions, divergent interpretations, and resulting spec/plan diffs. Confirm every completed implementation task has an actual commit and two-stage review result in `PLAN.md` and `AGENT_LOG.md`.

- [ ] **Step 2: Close remaining documentation-contract failures**

Run `pytest tests/distribution/test_artifacts.py -v`. For each failure, record it in `AGENT_LOG.md`, make the narrowest documentation or packaging correction, and rerun until the file passes.

- [ ] **Step 3: Update the task ledger and agent evidence**

For Tasks 1–12, enter actual commit hashes, implementing agent identity, specification-review result, code-quality-review result, and any human intervention in `PLAN.md` and `AGENT_LOG.md`. Include no invented hashes or retrospective claims without repository evidence.

- [ ] **Step 4: Verify hosted mock deployment and final CI**

Deploy the built container to the selected public host with no provider credential. Visit `/`, create the bundled demo task, and confirm the terminal page shows `SUCCEEDED`. Add the actual URL and deployment limitations to README. Record the final passing GitHub/GitLab pipeline URL or screenshot reference in `AGENT_LOG.md`.

- [ ] **Step 5: Run release verification and commit evidence**

Run: `pytest -q && ruff check src tests && python -m build && git status --short`
Expected: tests and lint PASS, package builds, and only the intended evidence-document edits are pending before commit.

```bash
git add SPEC.md PLAN.md SPEC_PROCESS.md AGENT_LOG.md README.md tests
git commit -m "docs: record cold-start and release verification evidence"
```

## Completion Gate

Before claiming completion, invoke `superpowers:verification-before-completion` and rerun the full release commands. Then invoke `superpowers:requesting-code-review` for an independent final review. Use `superpowers:finishing-a-development-branch` only after all critical review findings are fixed and the user is ready to choose merge/PR disposition.
+

## Cold-start Amendments for Tasks 1 and 8

Task 1 must implement the public-model, configuration-source, secure-default, argument-grammar, and status/iteration contracts in Specification section 14.1 before later tasks consume them. In particular, it produces `PolicyOutcome` and `PolicyDecision`, typed `ToolResult`, `QualityReport`, `TaskResult`, `ApprovalDecision`, and `AuditEvent`, and treats `pyquality.toml` as the sole repository configuration file.

Task 2 must expose compare-and-set transitions, approval lookup/decision/execution marking, durable transition intents, lease methods, and repository snapshots. Task 3 revalidation receives the saved `PolicyDecision`, supplied normalized action, and current snapshot digest; it denies digest mismatch or drift before reevaluating policy. Task 4 returns changed paths and before/after digests in `ToolResult`. Task 6 consumes those digests when making a stall decision. Task 7 exposes provider retry metadata only through the injected client policy; transport retries remain inside one model round.

Task 8 must use the state, round-accounting, approval, recovery, audit-sink, and idempotent-dispatch rules in Specification section 14.2. Its declared interface additionally includes `pending_approval(task_id: str) -> Approval`; its constructor receives all listed core protocols explicitly. Its tests must distinguish provider retries from model rounds and prove terminal resume idempotency, drift blocking, duplicate-decision rejection, and recovery of a persisted dispatch intent.
