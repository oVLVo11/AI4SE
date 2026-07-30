# Public Mock Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hosted public mock execute the existing deterministic offline demo and expose a truthful, sanitized `SUCCEEDED` result.

**Architecture:** Keep the public boundary synchronous and process-local. Inject a no-argument runner into `PublicDemoService`, convert the internal `DemoReport` into a small public evidence model, and render only fixed labels through the existing credential-free `TaskView.verification_summary` boundary.

**Tech Stack:** Python 3.12+, FastAPI, Pydantic v2, Jinja2, pytest, Ruff, existing `pyquality.demo.run_demo` composition.

## Global Constraints

- Public mode accepts only the bundled `broken_calculator` scenario and fixed task ID `public-demo`.
- No repository input, arbitrary prompt, external provider, credential service, database, worker, persistent disk, or paid resource may enter the public composition.
- Successful execution reports `TaskStatus.SUCCEEDED`, zero remaining rounds, and only bounded fixed evidence labels.
- Failures expose only `public demo execution failed`; exception text, type detail, paths, source, patch bodies, prompts, raw model output, timestamps, and audit payloads remain private.
- Results are process-local and replace the previous `public-demo` result on repeat execution.
- All implementation follows RED → GREEN TDD. Do not push a behavior commit until task review is clean.

---

### Task 1: Execute and Sanitize the Bundled Scenario

**Files:**
- Modify: `src/pyquality/web/app.py`
- Modify: `tests/web/test_public_mode.py`

**Interfaces:**
- Consumes: an injected `Callable[[], DemoReport]` and the existing `DemoReport` fields from `pyquality.demo`.
- Produces: `PublicDemoEvidence`, `PublicDemoService(scenarios, runner)`, `run_scenario(scenario_id) -> TaskView`, and `get_evidence(task_id) -> PublicDemoEvidence | None`.

- [ ] **Step 1: Add failing execution and sanitization tests**

Add a helper producing a literal `DemoReport` with `final_status=TaskStatus.SUCCEEDED`, denied-action evidence, fixed action order, assertion feedback, and no filesystem data. Add tests with these contracts:

```python
def test_public_scenario_executes_runner_and_returns_terminal_evidence() -> None:
    calls = 0
    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)
    task = service.run_scenario("broken_calculator")

    assert calls == 1
    assert task.status is TaskStatus.SUCCEEDED
    assert task.remaining_rounds == 0
    assert service.get_evidence(task.id) == PublicDemoEvidence(
        denied_action=True,
        denied_dispatch_count=0,
        first_failure_category="assertion",
        model_saw_first_failure=True,
        action_order=("read_file", "apply_patch", "apply_patch", "finish"),
    )


def test_public_scenario_failure_is_sanitized_and_retains_no_success() -> None:
    def runner() -> DemoReport:
        raise RuntimeError("secret C:/users/private/source.py prompt body")

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)
    with pytest.raises(PreflightError, match=r"^public demo execution failed$"):
        service.run_scenario("broken_calculator")
    assert service.get_evidence("public-demo") is None
```

Add a repeat-run test proving the runner is invoked twice and the second evidence replaces the first without retaining a list or session history.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
python -m pytest -p no:cacheprovider tests/web/test_public_mode.py -k "executes_runner or failure_is_sanitized or replaces" -v
```

Expected: FAIL because `PublicDemoService` has no runner/evidence interface and still returns `CREATED`.

- [ ] **Step 3: Implement the minimal public evidence boundary**

In `src/pyquality/web/app.py`, import `Callable`, `DemoReport`, and `PublicModel`. Add this frozen, extra-forbidden model:

```python
class PublicDemoEvidence(PublicModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    denied_action: bool
    denied_dispatch_count: int = Field(ge=0)
    first_failure_category: str
    model_saw_first_failure: bool
    action_order: tuple[str, ...]
```

Change the service constructor to accept `scenarios: Mapping[str, str]` and `runner: Callable[[], DemoReport]`. Its public methods have the exact signatures `run_scenario(self, scenario_id: str) -> TaskView` and `get_evidence(self, task_id: str) -> PublicDemoEvidence | None`.

`run_scenario()` validates the scenario, calls the runner, requires `report.final_status is TaskStatus.SUCCEEDED`, builds `PublicDemoEvidence`, then replaces the fixed task entry with a `TaskView` whose status is `SUCCEEDED`, remaining rounds are `0`, and verification summary is a fixed-label sentence derived only from the evidence fields. Convert every runner error or non-success report to `PreflightError("public demo execution failed") from None` and remove any previous task/evidence before re-raising.

- [ ] **Step 4: Run focused and complete public-mode tests**

Run:

```powershell
python -m pytest -p no:cacheprovider tests/web/test_public_mode.py -v
python -m ruff check src/pyquality/web/app.py tests/web/test_public_mode.py
```

Expected: all pass and Ruff reports `All checks passed!`.

- [ ] **Step 5: Commit Task 1**

```powershell
git add src/pyquality/web/app.py tests/web/test_public_mode.py
git commit -m "feat: execute bundled public mock scenario"
```

---

### Task 2: Compose the Offline Runner and Render Bounded Evidence

**Files:**
- Modify: `src/pyquality/cli.py`
- Modify: `tests/unit/test_cli.py`
- Modify: `tests/web/test_public_mode.py`

**Interfaces:**
- Consumes: `PublicDemoService(scenarios, runner)`, `run_demo(Path) -> DemoReport`, and `PublicDemoEvidence` from Task 1.
- Produces: production public-mock composition that runs in a fresh temporary directory and a task page containing only approved evidence labels.

- [ ] **Step 1: Add failing production-composition and page-boundary tests**

Update existing direct `PublicDemoService` constructions to inject deterministic runners. Add a production composition test that monkeypatches a new `_run_public_demo()` helper and proves `_default_app_factory(Path("."), "public_mock")` invokes it through form submission.

Add a page test requiring these literal fragments after POST redirect:

```python
assert "Status: succeeded" in response.text
assert "Remaining rounds: 0" in response.text
assert "Guardrail: outside action denied" in response.text
assert "Feedback: assertion" in response.text
assert "Progress: read_file -&gt; apply_patch -&gt; apply_patch -&gt; finish" in response.text
```

The same test must reject literal sentinel values placed in the runner exception/report fixture for a local path, source body, patch body, prompt body, provider key, and raw audit payload.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest -p no:cacheprovider tests/unit/test_cli.py tests/web/test_public_mode.py -k "public_mock" -v
```

Expected: FAIL because production composition does not inject a runner and the page lacks the approved labels.

- [ ] **Step 3: Add the production runner wrapper and bounded rendering**

In `src/pyquality/cli.py`, add:

```python
def _run_public_demo():
    from .demo import run_demo

    with TemporaryDirectory(prefix="pyquality-public-demo-") as directory:
        return run_demo(Path(directory))
```

Construct public mode with:

```python
PublicDemoService(
    {"broken_calculator": "public-demo"},
    _run_public_demo,
)
```

Keep template rendering limited to the existing escaped `verification_summary`; do not pass or iterate over the complete `DemoReport`. Format the summary in service code with exactly these fixed labels: `Guardrail`, `Feedback`, and `Progress`.

- [ ] **Step 4: Verify the complete local release path**

Run:

```powershell
python -m pytest -p no:cacheprovider tests/unit/test_cli.py tests/web/test_public_mode.py -v
python -m pytest -p no:cacheprovider -q
python -m ruff check src tests
python -m build --no-isolation
git diff --check
```

Run an isolated wheel server acceptance on a free local port: install the newly built wheel into a fresh temporary virtual environment, start `pyquality serve --host 127.0.0.1 --port <free-port> --public-mock`, submit the bundled form with its CSRF cookie, and require `/tasks/public-demo` to contain `Status: succeeded`, `Remaining rounds: 0`, and all three approved labels without any forbidden sentinel.

- [ ] **Step 5: Commit Task 2 and prepare review**

```powershell
git add src/pyquality/cli.py tests/unit/test_cli.py tests/web/test_public_mode.py
git commit -m "feat: expose sanitized hosted demo evidence"
```

Generate the task review package. Do not push until spec and quality review are clean. After review, resume the parent Task 13 deployment plan: push only with `git push origin HEAD:master`, require GitHub Actions green, require Render to deploy the exact commit, and repeat hosted acceptance before writing deployment evidence.
