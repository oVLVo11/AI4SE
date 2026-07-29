# Task 10A Atomic Lifecycle Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Task 10's final submission-compensation and cancellation races without weakening its durable recovery, bounded-resource, or security contracts.

**Architecture:** SQLite exposes two narrowly authorized transactional deletion operations: a CREATED-only user cancellation CAS and an owner-token-authorized RUNNING rollback. `HarnessService` routes every setup failure through one compensation routine that preserves the primary exception, independently attempts cleanup, reconciles durable state, removes only its own placeholder, and releases capacity exactly once.

**Tech Stack:** Python 3.12, SQLite `BEGIN IMMEDIATE`, `concurrent.futures`, pytest, Ruff.

## Global Constraints

- Implement the approved design in `docs/superpowers/specs/2026-07-29-task-10a-atomic-lifecycle-design.md` exactly.
- Task 10A documentation ancestry begins at design commit `f0c5fa4`; the SDD brief records the later execution-base commit after this plan is committed. Task 11 remains locked.
- Every production change requires a literal failing test first.
- Preserve Task 8 state/lease/recovery invariants and every independently clean Task 9/10 security boundary.
- Tests use deterministic barriers/events, not sleeps or scheduling luck.
- Public errors are typed and sanitized; the primary setup error wins over cleanup errors without chained internal exceptions.
- Root `PLAN.md`, `SPEC.md`, `SPEC_PROCESS.md`, `AGENT_LOG.md`, and the canonical Task 10 plan remain untouched until technical review is clean.

---

### Task 1: Transactional Cancellation, Authorized Rollback, and Unified Compensation

**Files:**
- Modify: `src/pyquality/storage/sqlite.py`
- Modify: `src/pyquality/service.py`
- Modify: `tests/unit/test_storage.py`
- Modify: `tests/unit/test_service.py`
- Modify only if an existing integration fixture is required: `tests/loop/test_approval_resume.py`

**Interfaces:**
- Consumes: `SQLiteTaskRepository` task/project/reservation/lease transactions; `HarnessService.create_task`, `start_task`, `cancel_task`, and durable recovery helpers.
- Produces: `SQLiteTaskRepository.cancel_created_task(task_id: str) -> bool`; `SQLiteTaskRepository.rollback_running_task(task_id: str, *, owner_token: str) -> bool`; unified service setup compensation with unchanged public CLI/Web signatures.

- [ ] **Step 1: Write failing CREATED cancellation CAS tests**

Add deterministic storage tests proving:

```python
assert repository.cancel_created_task(created.id) is True
assert repository.task_exists(created.id) is False
```

and, using a barrier between competing repository instances, prove a cancellation that loses to `CREATED -> RUNNING` returns `False` and leaves the live task, matching lease, project reservation, and project row intact. Add a two-canceller test proving exactly one `True` result. An unknown task must raise `StorageStateError` through the existing sanitized contract.

- [ ] **Step 2: Run cancellation tests and capture RED**

Run:

```powershell
python -m pytest tests/unit/test_storage.py -k "cancel_created or cancellation_cas" -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/pytest-cancel-red
```

Expected: FAIL because `cancel_created_task` is absent and unconditional discard can delete a task that won the RUNNING race.

- [ ] **Step 3: Implement the minimal CREATED-only transaction**

Within one existing write transaction:

1. Require the task row to exist.
2. Check status is exactly `CREATED`.
3. Check no iteration, approval, or project-lease evidence exists.
4. Delete the task's service reservation, task, and unused project only when all predicates still hold.
5. Return `False` on predicate loss without mutating durable state; return `True` only after committed deletion.

Do not call `discard_unstarted_task` from this API and do not transfer its reservation to unrelated low-level tasks.

- [ ] **Step 4: Rerun cancellation tests to GREEN**

Run the Step 2 command unchanged. Expected: PASS with no warnings.

- [ ] **Step 5: Write failing owner-authorized RUNNING rollback tests**

Add tests showing `rollback_running_task(task_id, owner_token=token)` returns `True` and atomically removes task, matching lease, service reservation, and unused project only when the task is RUNNING, has no iteration/approval evidence, and the current protocol lease owner matches. Prove wrong token, WAITING/terminal status, any iteration, and any approval return `False` without mutation. Unknown task raises `StorageStateError`.

- [ ] **Step 6: Run rollback tests and capture RED**

Run:

```powershell
python -m pytest tests/unit/test_storage.py -k "rollback_running" -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/pytest-rollback-red
```

Expected: FAIL because the authorized rollback API is absent.

- [ ] **Step 7: Implement the minimal owner-authorized transaction**

Validate the owner token with the existing helper, query task/evidence/current protocol lease in one write transaction, and delete only on an exact predicate match. After a committed delete, release only the matching process-local kernel lease. Predicate loss returns `False` and does not release another owner's local or durable lease.

- [ ] **Step 8: Rerun rollback tests to GREEN**

Run the Step 6 command unchanged. Expected: PASS with no warnings.

- [ ] **Step 9: Write failing service cancellation-race tests**

Using two `SQLiteTaskRepository`/`HarnessService` instances and events, reproduce the breaker interleaving: cancellation observes a candidate task, the other service transitions/acquires/enters the worker, then cancellation continues. Assert cancellation raises sanitized `PreflightError`, while the live task, owner lease, reservation, future, and worker remain valid. Add the inverse interleaving where cancellation commits first and `start_task` fails without retaining a placeholder or capacity permit.

- [ ] **Step 10: Run service race tests and capture RED**

Run:

```powershell
python -m pytest tests/unit/test_service.py -k "cancel_race or cancellation_winner" -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/pytest-service-cancel-red
```

Expected: FAIL because `cancel_task` uses a non-atomic snapshot plus unconditional delete and `start_task` can leak setup resources.

- [ ] **Step 11: Route cancellation through the CAS and reconcile locally after commit**

`cancel_task` must call `cancel_created_task` before destructively changing local maps. On `False`, raise a sanitized `PreflightError` and leave local/durable state untouched. On `True`, remove only identity-matching local entries. Ensure every `start_task` exception after capacity/placeholder acquisition enters the unified compensation path.

- [ ] **Step 12: Rerun service cancellation tests to GREEN**

Run the Step 10 command unchanged. Expected: PASS with no warnings.

- [ ] **Step 13: Write the setup-compensation failure matrix RED tests**

Parameterize primary failures at snapshot/path lookup, status transition, lease acquisition/busy result, and executor submission. Independently inject failures into lease release, `rollback_running_task`, durable task inspection, and local reconciliation. For every case assert:

```python
with pytest.raises(ExpectedPrimaryError):
    operation()
assert service_submission_registry_is_empty_or_recoverable()
assert capacity_can_be_acquired_by_new_work()
```

Also assert no exception cause/context exposes cleanup messages, tokens, paths, or requests. If authorized rollback fails and durable state remains RUNNING, assert no unresolved placeholder remains and the typed Web recovery path is available.

- [ ] **Step 14: Run the compensation matrix and capture RED**

Run:

```powershell
python -m pytest tests/unit/test_service.py -k "setup_compensation or primary_error_wins" -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/pytest-compensation-red
```

Expected: FAIL because `_prepare_submission` performs sequential cleanup and can mask the primary error or leak resources.

- [ ] **Step 15: Implement one unified best-effort compensation routine**

Use one internal routine for every setup failure after capacity or placeholder acquisition. It must retain the primary exception, attempt lease release and the correct CAS/authorized rollback independently, inspect durable existence/status, reconcile maps by placeholder identity, and release capacity exactly once in `finally`. It must leave durable RUNNING state recoverable when deletion is unauthorized or fails, never delete another owner’s work, and never re-raise cleanup failures.

- [ ] **Step 16: Rerun compensation and affected lifecycle suites**

Run:

```powershell
python -m pytest tests/unit/test_service.py tests/unit/test_storage.py tests/loop/test_agent_loop.py tests/loop/test_approval_resume.py tests/web/test_web.py -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/pytest-affected-green
```

Expected: PASS with only previously documented precise platform skips.

- [ ] **Step 17: Run final verification**

Run a pristine full suite with a fresh base temp, then:

```powershell
python -m ruff check src tests
git diff --check f0c5fa4..HEAD
```

Expected: full PASS with only precise existing skips; Ruff and diff check clean.

- [ ] **Step 18: Commit and prepare independent review**

Stage only authorized production/tests and commit:

```powershell
git commit -m "fix: make cancellation and compensation atomic"
```

Write `.superpowers/sdd/2026-07-29-task-10a-atomic-lifecycle/task-1-report.md` with literal RED/GREEN commands/output, concurrency reasoning, files, verification counts, and self-review. Generate the frozen review package from `f0c5fa4` to final HEAD. Do not update root course documents before independent review is clean.
