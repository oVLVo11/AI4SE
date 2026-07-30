# Task 11B Receipt Directory Durability Design

**Status:** Approved design; written specification pending user review

## Problem

Task 11A made receipt capacity crash-safe by durably reserving one pending event before creating its receipt. Its final independent review found one remaining POSIX durability gap: a newly created receipt is file-fsynced, but its parent directory is not fsynced before the pending checkpoint is durably cleared.

After a power loss, the cleared checkpoint may survive while the unsynced receipt directory entry disappears. The stream then has neither a pending reservation nor its committed receipt, so replay can recreate the same event identity and checkpoint receipt accounting can diverge from durable filesystem state.

Task 11B closes only this gap. Task 12 remains locked until Task 11B passes independent review.

## Durability Invariant

Creating a new POSIX receipt has one required publication order:

1. Create or securely open the exact receipt through the existing descriptor-relative, no-follow path.
2. Write and validate the bounded redundant receipt representation.
3. Fsync the receipt file.
4. If this operation created a new directory entry, fsync its immediate parent directory.
5. Only after step 4 succeeds, durably write the next checkpoint generation that clears the pending reservation and increments the committed receipt count.

The checkpoint must retain its pending reservation if receipt-file fsync or parent-directory fsync fails. No caller may report the event as committed or clear pending state after such a failure.

An existing receipt that is securely opened and verified does not require another parent-directory fsync because the current operation did not publish a new directory entry. Rewriting or repairing an existing receipt still requires the existing file durability rules.

## Component Boundary

The receipt commit helper owns the complete receipt-publication durability contract. It must distinguish whether it created a new directory entry and, on POSIX, synchronize the exact already-validated parent directory before returning success.

Both normal append and bounded suffix reconciliation call this helper. They may clear the pending checkpoint only after the helper returns successfully. This keeps the ordering invariant in one component and prevents the two workflows from drifting.

The implementation should reuse the existing hardened directory-sync primitive where its contract fits. Any small adapter must remain descriptor-safe and scoped to the already validated audit identity directory. It must not traverse arbitrary user-controlled paths or broaden permissions.

## Failure and Recovery Semantics

- Failure before receipt creation leaves the durable pending reservation unchanged.
- Failure after receipt creation but before file fsync leaves pending unchanged; restart uses existing pending recovery.
- Failure after file fsync but before or during parent-directory fsync also leaves pending unchanged. Restart may observe either the receipt or no durable directory entry and follows the existing bounded pending-recovery rules.
- Failure after parent-directory fsync but before checkpoint clearance leaves both a durable receipt and pending reservation. Restart verifies the receipt and completes the pending event exactly once.
- Only a successful parent-directory fsync permits checkpoint clearance for a newly created receipt.
- Errors remain typed and sanitized. They must not expose receipt paths, audit paths, event bodies, prompts, credentials, or owner tokens.

The change introduces no new recovery scan, receipt format, checkpoint format, public API, or capacity rule.

## Platform Semantics

On POSIX, the implementation fsyncs the immediate receipt parent directory after publishing a new receipt entry. Directory handles and paths must retain the existing no-follow, identity, ownership, and mode guarantees.

On Windows, existing handle, share-mode, reparse-point, owner, and ACL behavior remains unchanged. Task 11B does not emulate POSIX directory fsync or weaken Windows receipt publication.

Unsupported POSIX directory-fsync behavior must fail typed rather than silently clearing pending state. Tests may capability-skip only when the platform genuinely cannot exercise the primitive; ordinary injected failures are asserted, not skipped.

## Test Contract

Tests must first fail against commit `6de2411` and prove the ordering rather than claim to simulate physical power loss:

- normal append retains pending when parent-directory sync fails after receipt-file fsync;
- the cleared checkpoint is not written before parent-directory sync succeeds;
- a crash/fault after successful directory sync but before checkpoint clearance resumes exactly once;
- bounded suffix reconciliation obeys the same file-fsync, directory-fsync, checkpoint ordering;
- an already existing and verified receipt does not trigger an unnecessary new-entry directory sync;
- receipt creation, directory sync, and checkpoint-clear calls target the same validated audit identity root;
- the Task 11A reservation, migration-marker state matrix, R4-to-R5 migration, Windows ACL/token, audit-process, and full repository contracts remain green.

Fault tests use explicit seams or call recording and never sleeps. They must record genuine RED output before production changes and fresh GREEN output after the final commit.

## Scope and Review

Modify only the receipt durability implementation and focused security/component tests required by this invariant. Do not change receipt or checkpoint formats, public APIs, product/demo semantics, Task 9 credential contracts, Task 10 APIs, completed Task 11A migration behavior, root course documents, or Task 12 deliverables.

Task 11B is a distinct remediation task with a fresh five-round implementation-review budget. Task 11A remains historically blocked at its breaker; Task 11B is the only permitted path to close the remaining durability defect.
