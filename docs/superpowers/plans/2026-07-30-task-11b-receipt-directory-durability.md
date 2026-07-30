# Task 11B Receipt Directory Durability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every newly published POSIX audit receipt directory entry durable before its pending checkpoint reservation can be cleared.

**Architecture:** Extend the existing private receipt-commit boundary so it owns both file durability and, only for a newly created entry, synchronization of the receipt shard directory chain. Normal append and suffix reconciliation explicitly carry the creation fact and receipt parent into that boundary; checkpoint clearance remains after successful return.

**Tech Stack:** Python 3.13, descriptor-safe POSIX filesystem operations, existing Windows hardened handles/ACLs, pytest, Ruff.

## Global Constraints

- Implement `docs/superpowers/specs/2026-07-30-task-11b-receipt-directory-durability-design.md` exactly.
- Execution and cumulative review begin from the resolved HEAD containing this corrected plan; record that exact commit in the SDD brief before dispatch. Commit `83a6d7d` remains the production-behavior RED baseline because intervening commits change documentation only.
- No production code may be changed before a literal failing test has run against the execution base.
- Preserve receipt and checkpoint formats, public APIs, capacity accounting, Task 11A migration behavior, Windows ACL/reparse semantics, and typed sanitized errors.
- POSIX publication order is `create -> write -> file fsync -> receipt-parent directory fsync -> cleared checkpoint fsync`.
- Parent-directory sync failure must leave the pending checkpoint durable and uncleared.
- Existing verified receipts do not require directory sync when the current operation created no directory entry.
- Tests use explicit call recording and fault seams, never sleeps or claims of physically simulating power loss.
- Existing five deny-ACL pytest directories are environment residue and must not be staged, modified, or recursively enumerated.
- Preserve the existing dirty Task 11 controller progress file; do not stage it.
- Root course documents and Task 12 remain untouched until Task 11B review is clean.

---

### Task 1: Centralize New-Receipt Directory Durability

**Files:**
- Modify: `src/pyquality/security.py:831-883`
- Modify: `src/pyquality/security.py:1452-1489`
- Modify: `src/pyquality/security.py:1640-1684`
- Modify: `tests/security/test_redaction.py`
- Modify: `tests/component/test_audit_process.py` only if process-boundary evidence cannot be expressed in the security suite

**Interfaces:**
- Consumes: `_sync_audit_directory_chain(index_root: Path, leaf: Path) -> None`, `_store_audit_checkpoint(...) -> _AuditCheckpoint`, and the existing descriptor-relative receipt open/load/verify helpers.
- Produces: `_commit_audit_receipt(descriptor: int, event_id: str, offset: int, encoded: bytes, *, created: bool, index_root: Path, receipt_parent: Path) -> None`.
- Invariant: when `created` is true, successful return means the receipt file and its directory entry are durable; when false, successful return retains the existing file-only durability contract.

- [ ] **Step 1: Add normal-append ordering and failure RED tests**

Add focused POSIX tests that record calls to `_write_all`, receipt `os.fsync`, `_sync_audit_directory_chain`, and the pending/cleared `_store_audit_checkpoint` generations. Use a fresh event ID so the receipt is newly created.

The success assertion must encode this order:

```python
assert calls.index("receipt-file-fsync") < calls.index("receipt-directory-fsync")
assert calls.index("receipt-directory-fsync") < calls.index("clear-pending-checkpoint")
```

Inject `OSError("simulated directory sync failure")` from `_sync_audit_directory_chain`; reopen the checkpoint directly and assert:

```python
checkpoint = security._load_audit_checkpoint(checkpoint_descriptor)
assert checkpoint is not None
assert checkpoint.pending_event_id == event.event_id
assert checkpoint.committed_receipt_count == 0
```

Also inject a failure immediately after successful directory sync but before the cleared checkpoint store, reopen the logger, and assert one receipt and one JSONL event with `pending_event_id is None`.

- [ ] **Step 2: Run the normal-append tests and capture genuine RED**

Run with a basetemp outside the repository:

```powershell
D:\Python\python.exe -m pytest tests/security/test_redaction.py -k "receipt_directory_durability and normal_append" -v --basetemp "$env:TEMP\pyquality-task11b-red-normal"
```

Expected: fail against `83a6d7d` because receipt-file fsync is followed directly by the cleared checkpoint and no receipt-parent directory sync occurs.

- [ ] **Step 3: Add suffix-reconciliation and existing-receipt RED tests**

Create an unindexed, already-fsynced JSONL suffix and invoke the normal reopen/reconciliation path. Record the same ordering and inject the same directory-sync failure. Assert the reconciliation checkpoint retains that exact suffix event as pending and does not increment the committed count.

Create a second fixture with a valid existing receipt. Reopen/reconcile it while recording `_sync_audit_directory_chain` and assert no call is attributed to receipt publication by `_commit_audit_receipt`; checkpoint reconciliation must still succeed.

Assert the durability call is bound to the exact receipt shard:

```python
assert sync_calls == [(index_root, receipt_path.parent)]
```

- [ ] **Step 4: Run the reconciliation tests and capture genuine RED**

```powershell
D:\Python\python.exe -m pytest tests/security/test_redaction.py -k "receipt_directory_durability and (reconciliation or existing_receipt)" -v --basetemp "$env:TEMP\pyquality-task11b-red-reconcile"
```

Expected: the new-receipt reconciliation ordering test fails because no directory sync occurs. The existing-receipt characterization may already pass and must be recorded honestly.

- [ ] **Step 5: Implement the minimal centralized durability contract**

Change the private helper signature and keep the existing receipt write unchanged. Immediately after `os.fsync(descriptor)`, synchronize only a newly created entry:

```python
def _commit_audit_receipt(
    descriptor: int,
    event_id: str,
    offset: int,
    encoded: bytes,
    *,
    created: bool,
    index_root: Path,
    receipt_parent: Path,
) -> None:
    # Existing bounded slot construction and write remain here.
    _write_all(descriptor, payload)
    os.fsync(descriptor)
    if created:
        _sync_audit_directory_chain(index_root, receipt_parent)
```

At both call sites, determine creation before calling `_open_audit` and pass the exact derived parent:

```python
receipt_created = receipt_descriptor is None
if receipt_created:
    receipt_descriptor = _open_audit(receipt_path, append=False)

_commit_audit_receipt(
    receipt_descriptor,
    event_id,
    offset,
    encoded,
    created=receipt_created,
    index_root=index_root,
    receipt_parent=receipt_path.parent,
)
```

Do not catch directory-sync errors and do not move either cleared-checkpoint store earlier. Update existing direct test calls and monkeypatched wrappers to accept/pass the new keyword-only arguments without weakening their assertions.

- [ ] **Step 6: Run all Task 11B tests to GREEN**

Run the Step 2 and Step 4 commands unchanged. Expected: all Task 11B selectors pass; on POSIX the injected failure leaves pending state, and Windows-specific execution uses the existing no-op directory-chain behavior without ACL changes.

- [ ] **Step 7: Run adjacent reservation and migration regression suites**

```powershell
D:\Python\python.exe -m pytest tests/security/test_redaction.py tests/component/test_audit_process.py -v --basetemp "$env:TEMP\pyquality-task11b-affected"
```

Expected: pass with only explicit platform capability skips. In particular, the Task 11A marker×staging matrix, pending recovery, R4 migration, token-group, and parent-inheritance tests remain green.

- [ ] **Step 8: Run pristine repository verification**

```powershell
D:\Python\python.exe -m pytest -v --basetemp "$env:TEMP\pyquality-task11b-full"
D:\Python\python.exe -m ruff check src tests
git diff --check
```

Expected: pytest exits 0 at 100%; Ruff and diff checks exit 0. Record exact pass/skip counts and any capability skips.

- [ ] **Step 9: Commit the implementation**

Stage only the owned implementation and tests:

```powershell
git add src/pyquality/security.py tests/security/test_redaction.py tests/component/test_audit_process.py
git commit -m "fix: sync audit receipt directory entries"
```

Omit `tests/component/test_audit_process.py` from `git add` if it was not changed.

- [ ] **Step 10: Prepare the frozen review package**

Create `.superpowers/sdd/2026-07-30-task-11b-receipt-directory-durability/` with a brief, report, progress ledger, literal RED/GREEN outputs, the exact resolved execution/review base, production-behavior RED baseline `83a6d7d`, final commit, platform skips, and self-review. Generate a cumulative frozen diff from the recorded execution/review base to final HEAD, run `git diff --check` on it, and record its byte size and SHA-256. Do not update root course documents or dispatch Task 12.
