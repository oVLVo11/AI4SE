# Task 11A Audit Index Recovery Design

**Status:** Approved direction; written specification pending user review

## Problem

Task 11 reached its five-round breaker with two load-bearing audit-index defects. A distinct receipt file is created before the JSONL append and checkpoint commit, so a crash or pre-append failure can leave an uncounted file; repeated failures bypass the configured receipt cap. Separately, R4 stored sidecars beside the audit path while R5 uses a per-user identity root, but R5 does not discover the released R4 namespace. A valid R4 log larger than the bounded rebuild window therefore cannot replay after upgrade.

Task 12 remains locked until both defects pass independent review.

## Crash-Durable Receipt Reservation

The checkpoint format gains one durable pending reservation for the audit stream:

- `pending_event_id`: a 64-character lowercase hexadecimal event identity or null.
- `pending_start_offset`: the JSONL size before the reserved append.
- `committed_receipt_count`: the number of committed receipt identities; the existing cap applies to committed plus pending reservations.
- generation, indexed size, and checksum remain redundant across alternating checkpoint slots.

All operations run under the existing audit-inode process/thread lock and hardened descriptors.

For a new event:

1. Reconcile any prior pending reservation before accepting another event.
2. Check `committed_receipt_count + 1 <= max_receipts`.
3. Durably write a checkpoint generation containing the pending event and start offset.
4. Only then create/open its receipt and append/fsync the JSONL record.
5. Commit the redundant receipt slots.
6. Durably write the next checkpoint generation with the pending reservation cleared, indexed size advanced, and committed count incremented.

A failure before step 3 creates no receipt. A crash after step 3 leaves exactly one durable pending identity, preventing a second reservation until recovery. Thus each stream can have at most one uncommitted receipt file and total sidecar cardinality is bounded by the configured cap plus that single recoverable pending file.

## Pending Recovery

On every open/replay, pending recovery executes before normal capacity or duplicate checks:

- If no complete record exists at `pending_start_offset`, truncate only a bounded partial tail when permitted by the existing tail rules, securely remove the exact pending receipt if it exists, and clear the pending checkpoint without incrementing the committed count.
- If one complete matching event exists, verify its top-level event ID, record length, digest, and offset; create or repair the redundant receipt, then clear pending and increment the committed count.
- If the bytes contain a different complete event, exceed the record/recovery bound, or cannot be authenticated, fail with typed `AuditRecoveryRequired` without creating another sidecar or scanning beyond the configured limit.
- Receipt removal/opening remains descriptor-relative, no-follow, owner-only, and identity checked. Recovery never enumerates or deletes paths outside the exact stream identity root.

The bounded suffix reconciliation path uses the same durable reservation protocol for each newly discovered event. A crash during reconciliation resumes from the pending checkpoint and cannot create an uncounted series of receipts.

## R4 Namespace Migration

Before normal R5 replay, the logger checks for the exact released R4 namespace only when the new identity root has no completed migration marker.

The R4 candidate path is derived exactly from the opened audit file's lexical parent and exact opened-file identity. It is accepted only when:

- every path component is opened without following reparses/symlinks;
- the directory and files satisfy the existing current-token-owner and protected owner-only ACL/mode contract;
- its encoded identity equals the currently opened audit inode identity;
- checkpoint slots are checksummed and their indexed size is within the current JSONL size;
- each migrated receipt has a valid bounded name/format and matches the current JSONL bytes at its stored offset.

Migration copies at most the configured receipt cap into the new per-user identity root. It uses a durable migration marker containing source identity, target format version, next deterministic shard/name cursor, and completion state. Each receipt is copied through hardened descriptors and committed atomically in the new redundant format. A crash resumes from the marker; already copied matching receipts are idempotent. The new checkpoint is published only after all retained receipts and the indexed frontier are verified. Normal replay uses the new root only after a completed marker.

Invalid, ambiguous, over-cap, or identity-mismatched R4 data fails typed and sanitized; it is neither trusted nor silently deleted. The old namespace may remain as inert upgrade evidence and is never used after migration completion. Hardlink aliases converge on the same new identity root regardless of which alias performed migration.

If a new-root stream already contains committed R5 data, an R4 namespace is not merged into it. The new root remains authoritative, and inconsistent legacy evidence produces a typed migration conflict rather than duplicate receipts.

## Compatibility and Security

- The reservation checkpoint has a versioned decoder. Valid R5 checkpoints without pending fields upgrade as `pending=null`; corrupt or future versions fail typed.
- Stable event IDs, pre-SQLite sanitization, known-secret registration, raw-outbox quarantine, exactly-once outbox delivery, JSONL bounds, and receipt limits remain unchanged.
- No secret, absolute path, raw prompt/body, owner token, or lexical R4 path enters public errors, SQLite migration metadata, audit output, or deterministic demo evidence.
- Migration and recovery perform bounded work: at most the receipt cap, bounded receipt bytes, and bounded JSONL record reads. They never rescan the complete historical JSONL.

## Test Contract

Tests must first fail against `9f44513` and deterministically prove:

- repeated pre-append failures for distinct IDs leave at most one pending receipt and never exceed cap-plus-one sidecars;
- restart clears an append-never-started pending reservation and reuses capacity;
- restart completes append-fsynced but receipt/checkpoint-incomplete reservations exactly once;
- recovery and normal append races across processes cannot reserve two IDs past the cap;
- reconciliation crashes at each reservation/receipt/checkpoint stage resume idempotently;
- an actual R4 namespace with a valid log larger than 256 KiB migrates without full-log scanning and replays an old ID without duplication;
- migration interruption resumes, hardlink aliases share the completed target, and invalid/identity-mismatched legacy roots fail closed;
- Windows and POSIX descriptor/ACL/no-follow contracts remain intact;
- the complete Task 11 demo, outbox, security, storage, loop, and clean-wheel contracts remain green.

## Scope

Modify only the audit index/checkpoint/migration implementation and focused security/component tests required by these invariants. Do not change product behavior, demo semantics, Task 10 APIs, Task 9 credential contracts, or Task 12+ deliverables. Task 11A receives a fresh five-round review budget.
