# Task 11 Finish-Gated Success Design

**Status:** Approved direction; written specification pending user review

## Problem

The approved deterministic demo requires the real action order: denied read, incomplete patch, corrected patch after assertion feedback, then `finish`. The current `AgentLoop` terminalizes as soon as an `apply_patch` verification report succeeds, so it cannot consume the required `finish` action. Omitting `finish` would weaken the mechanism contract by treating a verifier result as an implicit model completion decision.

## Success Semantics

An action-triggered quality run no longer makes a task `SUCCEEDED` by itself.

- A failing quality report continues to produce normalized feedback and progress/stall accounting exactly as today.
- A passing quality report is persisted as the latest green completion candidate. It records the relevant repository digest, report identity, iteration, and verification summary needed to determine whether it is still current.
- After a green candidate, the loop requests the next typed model action with bounded context that visibly states that quality is green and that `finish` is now permitted.
- Only a valid `finish` action may transition `RUNNING -> SUCCEEDED`.

## Finish Validation

Before accepting `finish`, the loop must:

1. Confirm a latest green candidate exists for the task.
2. Confirm the repository's relevant digest still matches the candidate. Drift rejects that `finish` as bounded typed feedback, clears the candidate, and requires a later action-triggered quality run to establish a new candidate; stale evidence never succeeds.
3. Confirm deadline and lease ownership still permit work.
4. Run or reuse verification only under an explicit freshness rule. The chosen rule is to run one final quality verification on `finish`; success requires a passing full pytest result and Ruff result from that final run.
5. Persist the final report/result before publishing `SUCCEEDED` and release the lease through the existing terminal path.

`finish` before any green candidate, after a failing report, after drift, or after a failing final verification is rejected as typed feedback and consumes the existing bounded iteration/round budget. It does not bypass policy, verifier, approval, or deadline checks.

## State, Recovery, and Accounting

The green candidate is durable, not only process-local, so crash/resume can still consume a later valid `finish`. It is stored as a narrowly typed repository record keyed by task ID with candidate report identity, repository digest, iteration, and bounded summary. Replacing or clearing the candidate is transactional with the corresponding task/iteration transition. It never stores raw prompts, source bodies, or unbounded output.

Provider retries remain outside model-round accounting. The corrected patch and the later `finish` are separate persisted model/action iterations. A passing patch may reset relevant progress/stall evidence but does not add an artificial verifier-only model round. Terminal resume stays idempotent.

WAITING_APPROVAL, rejection, lease handoff, dispatch-intent recovery, and Task 10A service lifecycle behavior remain unchanged.

## Context and Audit

The context after a green patch includes only bounded structured evidence: quality-green status, normalized verification summary, changed paths, remaining rounds, and the instruction that `finish` is allowed. It excludes complete prompts/responses, source bodies, secrets, absolute temporary paths, and timestamps from deterministic fingerprints.

Audit events distinguish `quality_candidate_ready`, `finish_verification`, and terminal success using the existing centralized redaction boundary.

## Test Contract

Tests must first fail against the current implicit-success behavior and prove:

- a corrected patch that passes verification leaves the task RUNNING and causes the scripted `finish` action to be consumed;
- the post-green context says quality is green and permits `finish`;
- `finish` without a green candidate cannot succeed;
- repository drift between green patch and `finish` cannot use stale evidence;
- final verification failure returns feedback rather than success;
- crash/resume after the green candidate can finish successfully;
- deadline, lease, iteration, approval, terminal-idempotency, and audit-redaction regressions remain green;
- the Task 11 demo uses the exact four-action sequence and is deterministic/offline.

## Scope

Modify only the loop/storage/domain/context surfaces required to persist and consume the green candidate, plus focused loop/storage tests and the Task 11 demo. Do not change the public Task 10 API, security boundaries, action schema, verifier success definition, or Task 12+ scope.
