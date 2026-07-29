# Task 10A Atomic Lifecycle Remediation Design

**Status:** Approved direction; written specification pending user review

## Problem

Task 10 reached its five-round review breaker with two load-bearing lifecycle defects. Submission preparation can encounter a primary failure and then stop at the first compensation failure, masking the primary error while leaking capacity, a placeholder future, and durable RUNNING/reservation state. Separately, cancellation reads CREATED outside the deletion transaction, so another service can transition and lease the task before an unconditional delete removes live work.

Task 11 must not begin until both defects are corrected and independently reviewed.

## Chosen Architecture

Cancellation and internal rollback become separate storage operations with separate authority:

- `cancel_created_task(task_id) -> bool` is a transactional compare-and-delete. It returns `True` only after deleting a task that is still `CREATED`, has no iterations or approvals, and has no execution lease. It returns `False` for a known task that lost any of those predicates, without deleting any task, lease, reservation, or project; an unknown task raises the existing sanitized storage-state error.
- `rollback_running_task(task_id, *, owner_token: str) -> bool` is an owner-authorized transactional rollback for a submission that transitioned the task but did not dispatch work. It returns `True` only while the task is `RUNNING`, the matching current lease row uses the supplied owner token and protocol, and no iterations or approvals exist. It atomically deletes the owned lease, task, service reservation, and now-unused project. It returns `False` for predicate loss; an unknown task raises the existing sanitized storage-state error.
- Neither operation silently transfers a service reservation to an unrelated low-level task. Existing migration behavior remains compatible with databases created before Task 10A.

`HarnessService.cancel_task()` calls only the CREATED CAS. It performs no destructive in-memory cleanup before the CAS succeeds. After success it removes identity-matching local entries. If the CAS loses a race, it raises a sanitized typed error and leaves the winning submission untouched.

## Unified Setup Compensation

Every exception after capacity or placeholder acquisition, including snapshot/path lookup, CREATED-to-RUNNING transition, lease acquisition, and executor submission, enters one compensation routine.

The routine:

1. Preserves the primary exception for the caller.
2. Runs lease release, authorized rollback/CAS, future removal, local-map reconciliation, and capacity release as independent best-effort steps.
3. Releases the capacity permit in `finally`, exactly once.
4. Removes the placeholder by identity so it cannot remove another caller's future.
5. Inspects durable state after cleanup. If the task was deleted, all local reservation/owner state is removed. If a RUNNING task remains, its owner and repository reservation remain recoverable but no never-completing future remains. If another actor won the race, local state is reconciled without deleting that actor's lease or task.
6. Never lets a cleanup exception replace the primary exception. Cleanup details remain sanitized and do not expose paths, requests, owner tokens, or exception chains.

The existing successful dispatch, approval recovery, WAITING_APPROVAL reservation, bounded future registry, public mock, stateless session, and AgentLoop cache behavior remain unchanged.

## Concurrency Invariants

- A task deletion decision and the status/lease/evidence checks authorizing it occur in one `BEGIN IMMEDIATE` transaction.
- User cancellation never deletes RUNNING, WAITING_APPROVAL, or terminal tasks.
- Internal rollback never deletes a RUNNING task owned by another token or a task with execution evidence.
- No failure path leaves an unresolved placeholder while also returning an exception to the caller.
- Each accepted capacity permit has exactly one release, even when multiple cleanup operations fail.
- Concurrent `start_task`, `cancel_task`, recovery, and independent repository instances resolve through database CAS and kernel/durable lease ownership, not process scheduling luck.

## Error Contract

CAS conflicts surface as typed, sanitized `PreflightError` or `ProjectBusyError` according to the public operation. Missing tasks, status races, owner mismatches, and cleanup failures do not expose SQLite messages, repository paths, tokens, or chained internal exceptions. The original setup error remains the observable error when compensation also fails.

## Test Design

Tests must first fail against `3b3859f` and use deterministic barriers rather than timing:

- Pause cancellation after it starts, let an independent service transition/acquire/enter its worker, then prove cancellation loses without deleting the live task, lease, or reservation.
- Delete a genuinely CREATED task and prove its service reservation/project cleanup is complete.
- Force failure at snapshot/path lookup, transition, lease acquisition, and executor submission; inject failures independently into lease release, authorized rollback, durable inspection, and local cleanup.
- Prove the primary exception is preserved, capacity is reusable, the future registry is bounded, and remaining RUNNING state is Web-recoverable.
- Race two cancellation callers and prove at most one succeeds.
- Verify owner-token mismatch and execution evidence prevent internal rollback.
- Run affected service/storage/loop/Web suites, a pristine full suite, Ruff, and cumulative diff checks.

## Scope

Modify only the service/storage lifecycle implementation and focused tests required by these invariants. Do not change Task 10 public product scope, Task 11 behavior, root course documents, credential/audit contracts, public mock capability, or session design. Implementation remains a fresh Task 10A SDD task with its own five-round review budget.
