# Task 11A Audit Index Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make receipt capacity crash-durable and migrate the released R4 audit-adjacent sidecar namespace into the secure R5 identity namespace without unbounded log scanning.

**Architecture:** The redundant checkpoint stores one durable pending receipt reservation before any sidecar creation. Recovery completes or clears that reservation before another event is admitted. A versioned, identity-verified migration copies bounded R4 checkpoint/receipt evidence into the global identity root through hardened descriptors and a resumable marker.

**Tech Stack:** Python 3.13 runtime, cross-platform descriptor-safe filesystem operations, JSONL, pytest, Ruff.

## Global Constraints

- Implement `docs/superpowers/specs/2026-07-30-task-11a-audit-index-recovery-design.md` exactly.
- Execution begins after this plan commit; record the resolved base in the SDD brief.
- No production code without a literal failing test first.
- Tests use fault seams/events and explicit process synchronization, never sleeps.
- Preserve Task 9 owner-only/no-follow audit security, Task 11 outbox exactly-once semantics, known-secret sanitization, and bounded recovery.
- Never scan the complete historical JSONL to migrate or recover.
- Existing five deny-ACL pytest directories are environment residue and must not be staged, modified, enumerated recursively, or treated as product files.
- Root course documents and Task 12 remain untouched until Task 11A review is clean.

---

### Task 1: Crash-Durable Receipt Reservations

**Files:**
- Modify: `src/pyquality/security.py`
- Modify: `tests/security/test_redaction.py`
- Modify: `tests/component/test_audit_process.py` only for cross-process coverage

**Interfaces:**
- Consumes the current redundant checkpoint, receipt, descriptor-lock, tail-recovery, and index-root helpers.
- Produces a versioned checkpoint with `pending_event_id` and `pending_start_offset`; no public `AuditLogger` signature change is required.

- [ ] **Step 1: Add checkpoint compatibility RED tests**

Create tests for decoding a valid R5 checkpoint as `pending=None`, writing/reading the new pending generation, rejecting corrupt/future formats, and preserving the older valid slot when the newest pending slot tears.

- [ ] **Step 2: Run the checkpoint tests and capture RED**

Run a focused `pytest` selector with a basetemp outside the repository. Expected: fail because the checkpoint model lacks pending state.

- [ ] **Step 3: Implement the versioned redundant checkpoint**

Extend the fixed-size/checksummed slots without unbounded allocation. Old valid slots decode with null pending. Validate the pending ID and offset against the indexed/file size bounds. Do not create any receipt in this step.

- [ ] **Step 4: Rerun checkpoint tests to GREEN**

Run the Step 2 command unchanged. Expected: pass without warnings.

- [ ] **Step 5: Add pre-append failure and restart RED tests**

With the cap set to one, inject failure/crash after pending-checkpoint fsync, after receipt creation, before append, after append fsync, after receipt commit, and before final checkpoint. For distinct IDs, assert at most one uncommitted receipt and never more than cap-plus-one files. Reopen and prove capacity is reusable or the appended event is completed exactly once.

- [ ] **Step 6: Add reconciliation and concurrency RED tests**

Crash during bounded suffix reconciliation at reservation, receipt, and checkpoint stages. Add two-process synchronization showing only one distinct ID can reserve the last capacity slot and the loser creates no sidecar. Assert malformed/mismatched pending bytes fail typed without another create.

- [ ] **Step 7: Run reservation tests and capture RED**

Expected: fail against `9f44513` because receipt creation is not preceded by a durable reservation and orphan cardinality grows.

- [ ] **Step 8: Implement pending reservation and recovery**

Under the existing audit-inode lock, reconcile pending first, durably reserve before create, then append, commit receipt, and clear/increment checkpoint. Apply the same protocol to suffix reconciliation. Remove only the exact orphan receipt after descriptor-relative validation. Capacity counts committed plus pending.

- [ ] **Step 9: Rerun reservation/security/component tests to GREEN**

Run focused tests, full `tests/security`, and audit-process component tests. Expected: pass with only explicit platform capability skips.

- [ ] **Step 10: Commit Task 1**

Commit `fix: reserve audit receipts before creation`.

### Task 2: Bounded R4 Namespace Migration

**Files:**
- Modify: `src/pyquality/security.py`
- Modify: `tests/security/test_redaction.py`
- Modify: `tests/component/test_audit_process.py` if cross-process migration needs it

**Interfaces:**
- Consumes the released R4 directory format from commit `90b9c45` and the Task 1 checkpoint format.
- Produces a versioned resumable migration marker and a completed R5 identity root.

- [ ] **Step 1: Build an exact R4 fixture and capture replay RED**

Using the released R4 format, create a valid >256 KiB JSONL, checkpoint, and receipts at `audit.parent/.pyquality-audit-index-{opened_identity}`. Reopen with current code and replay an old event. Expected: `AuditRecoveryRequired`, proving old namespace invisibility.

- [ ] **Step 2: Add identity/security failure RED tests**

Test wrong encoded identity, symlink/reparse component, permissive/foreign owner, corrupt checkpoint, over-cap receipts, receipt/log mismatch, and simultaneous conflicting new-root data. Each must fail typed without copying data or leaking the legacy path.

- [ ] **Step 3: Add interruption/alias RED tests**

Inject migration crashes before marker, during deterministic receipt copying, after receipt fsync, and before completed marker. Reopen through another hardlink alias in another directory/process and require resumable convergence on one target with no duplicate JSONL record.

- [ ] **Step 4: Implement secure discovery and resumable migration**

Only when the new root lacks a completed marker, derive the exact R4 candidate from the opened alias and identity. Open every component no-follow and verify owner-only metadata. Copy at most the receipt cap through hardened descriptors, validate each receipt against bounded JSONL offsets, and advance a checksummed durable cursor. Publish the new checkpoint/completed marker last. Never merge with existing committed R5 data.

- [ ] **Step 5: Rerun migration tests to GREEN**

Run all new migration selectors plus full security/component suites. Expected: pass with bounded reads and only explicit capability skips.

- [ ] **Step 6: Run final Task 11A verification**

Run affected security/storage/loop/e2e/application/service tests, clean-wheel demo verification, pristine full suite, `python -m ruff check src tests`, and cumulative `git diff --check` from the execution base.

- [ ] **Step 7: Commit and prepare review**

Commit `fix: migrate legacy audit index safely`. Update `.superpowers/sdd/2026-07-30-task-11a-audit-index-recovery/task-1-report.md` and ledger with literal RED/GREEN outputs, crash protocol, migration bounds, skips, commits, and self-review. Generate a frozen cumulative review package from the execution base to final HEAD. Do not update root course documents or dispatch the reviewer.
