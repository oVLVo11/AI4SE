# Task 11 implementation report

## Scope and commits

- Base: `b8f2fe2`; approved design/plan: `23aed39`, `55ea73e`.
- `593384e feat: persist green completion candidates`
- `e80a17d feat: gate task success on finish`
- `6dcc2ec fix: recover finish-gated completion evidence`
- `16b4edc feat: add deterministic harness mechanism demo`
- `ba8d95b test: migrate loop contracts to finish-gated success`
- Root course documents were not modified.

## TDD evidence

1. Candidate storage RED: `python -m pytest tests/unit/test_storage.py -k green_candidate -v -p no:cacheprovider --basetemp .test-tmp/task11-red-storage` failed at import because `GreenCandidate` did not exist. GREEN: the same focused cluster passed 4 tests; complete `tests/unit/test_storage.py` passed 71 tests.
2. Finish gate RED: `python -m pytest tests/loop/test_agent_loop.py -k "passing_patch_requires_finish or finish_without_green or failing_final or repository_drift" -v ...` produced four expected failures: implicit patch success consumed one call, unsupported finish had the old result, final failure was skipped, and drift did not cause re-verification. GREEN: all four passed after the gate implementation.
3. Recovery RED: `python -m pytest tests/loop/test_agent_loop.py -k "survives_crash_and_resume or green_and_finish_audit" -v ...` proved the reopened prompt lacked durable green context. GREEN: crash/reopen consumed a distinct finish, and candidate/finish audit events were bounded and path-free.
4. Demo RED: `python -m pytest tests/e2e -v ...` failed collection because `pyquality.demo` was absent. GREEN: all four e2e contracts passed, including offline isolation, normalized double-run equality, and default CLI JSON.
5. Pristine full initially exposed 33 historical tests encoding implicit success. Authorized migration mapping: bare `finish` -> real `run_quality` + distinct `finish`; approval/recovery passing report -> subsequent real quality candidate + final verification; crash recovery -> recovered feedback, real quality action, then finish. Lease, dispatch-count, approval, deadline, recovery, and idempotency assertions were retained; verifier-call assertions were increased where the new final verification is required.

## Evidence provenance

- Policy denial is the persisted first iteration; the recording wrapper proves the denied `read_file("../secret")` never reaches the real `ToolDispatcher`.
- Both patches are executed by the real dispatcher. The first real `QualityPipeline` report supplies the assertion finding and feedback visible in the third recorded `ScriptedLLM` context.
- The corrected patch creates the durable candidate from a real passing full pytest/Ruff report. The fourth persisted action is `finish`, which performs a separate final real verification.
- Normalized events come from persisted iterations, policy outcomes, quality outcomes, fingerprints, and actual dispatcher observations. Temporary paths, timestamps, prompt/source bodies, and credentials are excluded.

## Final verification

- `python -m pytest tests/loop -q -p no:cacheprovider --basetemp .test-tmp/task11-loop-migrated`: passed.
- `python -m pytest -q -p no:cacheprovider --basetemp .test-tmp/task11-full-final`: 482 collected; 474 passed, 8 skipped, zero failures.
- `python -m ruff check src tests examples`: all checks passed.
- `git diff --check`: passed.
- `.test-tmp` was resolved to the worktree-local path and removed.

## Self-review

- Candidate fields are frozen, digest-bound, bounded, path-normalized, task-isolated, reopen-durable, and cleared on terminal transition.
- A passing non-finish report no longer terminalizes; missing/stale candidates and failing final verification cannot succeed.
- The demo makes no provider/keyring/network call and copies only its bundled fixture into a disposable repository.
- CLI failure is typed and sanitized; success JSON is schema-versioned and contains no absolute path.

## Formal review round 1

The authoritative review reported two Critical findings: stale finish success after a
policy/verifier-intent crash followed by repository drift, and approved passing-patch
recovery terminalizing without a candidate or distinct finish. It reported six Important
findings: non-transactional candidate lifecycle and missing bounds/ownership; approved
patches masked by artificial quality rounds; missing post-final deadline/lease/digest
checks; fixed post-green text omitting persisted evidence; demo fixture/evidence not
actually packaged/derived; and incomplete typed CLI/demo failure containment. No other
findings were reported.

Fix commits:

- `d60a8bc fix: make finish evidence crash-safe`
- `10339c0 fix: package and sanitize deterministic demo`

RED/GREEN mapping:

- Crash after the second completed verifier intent, mutate the repository, reopen: RED
  reused the report with zero pipeline calls; GREEN binds verifier intent evidence to the
  actual repository digest and performs two new real verifications before success.
- Green candidate followed by failed quality then finish: RED reached a third verifier;
  GREEN clears the candidate atomically with the failing iteration and rejects finish.
- Final verifier crossing the deadline: RED succeeded; GREEN persists the verifier round
  and terminalizes `BUDGET_EXHAUSTED` after the post-verifier check.
- Approved patch then finish with two reports: RED exhausted the scripted model; GREEN
  atomically persists the passing approved iteration, candidate, and completed approval,
  then consumes one distinct finish/final verification. Crash-after-atomic-pass recovery
  proves exact-once dispatch and two verifier calls.
- Candidate/terminal transaction failures: injected RED-risk boundaries now roll back the
  iteration together with candidate and roll back final iteration/result/cleanup together.
- Post-green context RED omitted changed paths and rounds; GREEN renders persisted bounded
  summary, relative changed paths, and computed remaining rounds through ContextBuilder.
- Packaged fixture RED raised `ModuleNotFoundError`; GREEN copies via
  `importlib.resources`. Report attempted state, action order, and patch digests now derive
  from persisted actions and real dispatcher observations.
- Forced demo and outer CLI temp setup failures RED leaked `OSError`; GREEN returns nonzero
  stable path-free JSON without traceback.

After `hatchling` became available, the clean-wheel test built the distribution, inspected
the packaged resources, installed into a clean target, and ran `demo --json` outside the
source checkout. A dedicated 360-byte post-green context regression also proves truncation
and absolute-path exclusion. Final round-1 verification collected 492 tests: 484 passed and
8 skipped. Ruff and cumulative diff-check passed.

## R2 evidence correction chronology

The atomic-finish implementation preceded two dedicated regression tests, so this is
recorded as a transparent post-implementation evidence correction, not original TDD.
The same three tests were run in an isolated detached worktree at `22ddadd` with its
`src` directory explicitly first on `PYTHONPATH`: all three failed behaviorally
(stale candidate cleared before round persistence, late report committed before
terminal cleanup, and approved candidate bound to the tool/approval digest rather
than the actual `QualityReport` digest). On the corrected branch the exact three
tests passed. Fresh final verification reported 487 passed, 8 environment skips;
Ruff and `git diff --check` passed.

## Formal review round 2 remediation (round-3 takeover)

The original round-3 agent exhausted its context after starting the fix. The takeover
preserved every inherited working-tree edit, reconstructed the frozen cumulative review
range `b8f2fe2..5ad427a`, and completed the remaining findings under the required commit
subject `fix: recover finish evidence and audit outbox`. Root course documents and
reviewer-owned files were not modified.

The binding findings were:

- a passing approved action whose approval already says `completed` must repair a missing
  candidate from the persisted verifier transition, consume that intent exactly once, and
  still require a distinct final verifier after a later `finish`;
- `quality_candidate_ready`, `finish_verification`, and `task_terminal` evidence must be
  committed atomically with the lifecycle state it describes, survive sink failure and
  restart, and be drained before a terminal fast-return;
- sink success followed by acknowledgement failure must replay the same stable ID without
  creating a second observable JSONL record;
- IDs, durable payloads, delivery batches, scan memory, metadata, and recovery work must
  remain typed, bounded, ordered, and redacted.

### Round-3 RED/GREEN evidence

1. The inherited model RED required every production `AuditEvent` to carry a 64-character
   lowercase hexadecimal `event_id`. On takeover the model slice was GREEN while the
   approval recovery slice still failed because loop producers had not propagated the new
   required field.
2. The first storage RED cluster failed collection because `AuditOutboxRecord` and outbox
   APIs did not exist. GREEN added ordered reopen-durable rows and atomic enqueue to
   candidate, iteration, approval-completion, and terminal transactions. Injecting an
   enqueue failure proves the candidate, iteration, terminal result, approval completion,
   and events roll back together. A separate RED showed a 20,000-byte event was accepted;
   GREEN rejects any durable event over 16,384 bytes before commit.
3. `test_audit_logger_replay_of_same_event_id_is_observable_once` was RED with two JSONL
   lines. GREEN performs recovery, exact-ID detection, append, and `fsync` under the same
   descriptor lock, so a replay is a no-op.
4. The two loop crash tests were RED with missing-ID validation errors. GREEN proves
   commit -> sink failure -> restart drains candidate, finish, and terminal evidence in
   order before returning the saved terminal result, with zero new model/verifier calls.
   It also proves sink success -> repository-mark failure reuses all three persisted IDs
   and leaves each event observable once.
5. The completed-approval recovery regression now leaves the approval truly `completed`,
   removes only its candidate, closes and reopens SQLite, repairs the candidate while
   consuming the saved verifier intent, and then runs a distinct final verifier. The
   dispatcher remains exact-once and the verifier call count is two.
6. Final self-review found that delivered rows were only timestamped and would accumulate.
   `python -m pytest tests/unit/test_storage.py::test_delivered_audit_outbox_rows_are_pruned_and_reack_is_harmless -q -p no:cacheprovider --basetemp "$env:TEMP\\pyquality-task11-r3-prune-red"`
   failed with `retained_rows == 1`. GREEN physically deletes the oldest row after sink
   acknowledgement, treats acknowledgement replay as harmless, and retains only pending
   recovery work. The three focused ordering/pruning tests then passed.
7. Final scan review found that the bounded byte-substring search could mistake a nested
   `event_id` in an oversized legacy line for a top-level ID. The focused RED command
   `python -m pytest tests/security/test_redaction.py::test_audit_id_scan_ignores_nested_id_in_oversized_legacy_record tests/security/test_redaction.py::test_audit_id_scan_detects_top_level_id_across_read_boundary -q -p no:cacheprovider --basetemp "$env:TEMP\\pyquality-task11-r3-audit-scan-red2"`
   failed the nested-ID case. GREEN parses complete JSONL records with a 16,384-byte record
   buffer, skips malformed/oversized records, reads only 64 KiB at a time, and still finds
   a valid top-level ID spanning two reads; the replay plus both boundary tests passed 3/3.

### Round-3 protocol and bounds

- The loop creates each critical event once before commit. SQLite serializes it in the
  same transaction as the candidate/finish/terminal state, keyed by a unique persisted
  64-character lowercase hexadecimal ID and ordered by an autoincrement sequence.
- Delivery reads a validated batch of 1-128 records and drains one oldest record at a
  time. Sink failure or mark failure leaves that row pending. Successful acknowledgement
  deletes it, preventing delivered tombstone growth; a permanent sink outage necessarily
  retains only the still-undelivered recovery evidence.
- Every task entry drains the global oldest pending event before reading terminal state.
  The JSONL sink uses its existing hardened owner-only/no-follow descriptor and
  cross-process lock; recovery, bounded exact top-level-ID scan, append, and `fsync` share
  that lock. Thus a crash after append but before SQLite acknowledgement safely replays the
  stable ID without a duplicate line.
- Production construction was exhaustively checked: the loop is the only producer and
  supplies a fresh stable ID, while service export is the only decoder and restores the
  persisted ID. The durable event envelope is capped at 16,384 bytes and passes through the
  centralized audit metadata allowlist; no prompt, source body, secret, or absolute path is
  added to the outbox.

### Round-3 modified files

- Runtime: `src/pyquality/domain/models.py`, `src/pyquality/storage/sqlite.py`,
  `src/pyquality/loop.py`, `src/pyquality/security.py`, `src/pyquality/service.py`, and
  `src/pyquality/demo.py`.
- Tests: `tests/unit/test_models.py`, `tests/unit/test_storage.py`,
  `tests/unit/test_service.py`, `tests/loop/conftest.py`,
  `tests/loop/test_agent_loop.py`, `tests/loop/test_approval_resume.py`,
  `tests/security/test_redaction.py`, and `tests/component/test_audit_process.py`.

### Round-3 final verification

- `python -m pytest -p no:cacheprovider --basetemp "$env:TEMP\\pyquality-task11-r3-final-full"`:
  499 passed, 8 skipped in 37.07 seconds.
- `python -m ruff check src tests examples`: all checks passed.
- `git diff --check`: exit 0; only the repository's existing LF/CRLF conversion warnings
  were printed.
- Focused storage ordering/pruning, JSONL replay/scan boundaries, loop restart repair,
  completed-approval cold recovery, service export, security, component, and e2e slices
  were also GREEN before the pristine full run.

## Formal review round 4 remediation

Round 4 addressed two binding findings without modifying root course documents or
reviewer-owned files:

- raw `AuditEvent` payloads were serialized into SQLite before the JSONL sink's central
  sanitizer ran, so a failed sink could leave nested sensitive fields, bearer tokens,
  sensitive URL query values, absolute paths, and configured secrets at rest;
- replay scanned the complete JSONL history on every append, while malformed unterminated
  tails could require unbounded recovery memory and I/O.

### Round-4 RED/GREEN evidence

1. `test_pending_audit_outbox_stores_only_prepared_redacted_payload` was RED because
   `AuditLogger.prepare` did not exist and the outbox stored the raw event before sink
   delivery. GREEN injects the logger's central preparation function into SQLite and
   asserts the failed-delivery row contains none of the configured secret, bearer token,
   URL credential, absolute path, or nested sensitive metadata.
2. Four audit-index tests were RED against the prior full-file scan: replay of a middle
   historical ID read beyond the 64 KiB allowance; a 1 MiB unterminated tail was silently
   read and truncated; and the receipt-commit and record-write crash seams did not exist.
   GREEN replays an old ID without changing the log, refuses the huge malformed tail with
   typed bounded behavior and no truncation, recovers append-before-index exactly once,
   and retries pre-append failure as one observable line.
3. A receipt-cap RED failed because no durable cardinality bound existed. GREEN caps
   committed receipts at 16,384: an already indexed event remains replayable at the cap,
   while the next distinct event fails closed with `AuditRecoveryRequired`.
4. Follow-up regressions prove that corruption of the newest checkpoint slot falls back
   to the prior valid slot plus bounded reconciliation, and service export emits only the
   canonical JSONL records rather than adjacent index artifacts.

### Round-4 protocol and bounds

- `sanitize_audit_event` is the single preparation boundary shared by direct JSONL writes
  and every SQLite enqueue path. The repository applies it inside the lifecycle
  transaction before serialization, revalidates event identity, and enforces the 16 KiB
  envelope both before and after preparation. `build_service` supplies the logger-bound
  configured secret registry to the repository.
- Under the hardened audit-file lock, recovery first inspects only the final byte. A
  partial final record is repaired with at most 64 KiB of backward scanning; a larger
  unterminated tail is left unchanged and raises `AuditRecoveryRequired`.
- A file-identity-scoped sidecar index uses two fixed 64-byte checkpoint slots and
  sharded receipts no larger than 512 bytes. Checkpoints carry generation, indexed JSONL
  size, receipt count, and checksum. A damaged newest slot falls back to the older valid
  slot, and unindexed reconciliation is capped at 256 KiB rather than scanning history.
- Append and `fsync` precede durable receipt commit and checkpoint advancement. Therefore
  append-before-index crashes are reconciled without a duplicate, while failures before
  append leave no committed receipt and retry normally. Receipt lookup verifies the
  exact bounded record bytes at the stored offset before treating an ID as delivered.
- Audit, checkpoint, and receipt paths use the existing descriptor-relative no-follow,
  owner-only open and file-locking discipline. Platform-native file identity isolates the
  sidecar namespace, and export reads only the requested JSONL file.

### Round-4 modified files

- Runtime: `src/pyquality/application.py`, `src/pyquality/security.py`, and
  `src/pyquality/storage/sqlite.py`.
- Tests: `tests/security/test_redaction.py`, `tests/unit/test_service.py`, and
  `tests/unit/test_storage.py`.

### Round-4 final verification

- `python -m pytest -p no:cacheprovider --basetemp "$env:TEMP\\pyquality-task11-r4-final-full"`:
  507 passed, 8 skipped in 42.90 seconds.
- `python -m ruff check src tests examples`: all checks passed.
- `git diff --check`: exit 0; only the repository's existing LF/CRLF conversion warnings
  were printed.
- Focused sanitizer-at-rest, audit replay/crash/cap/checkpoint, security, storage,
  service/export, loop, application, and component slices were GREEN before the pristine
  full run. One earlier full-suite run had a single scheduling-sensitive cleanup failure;
  that test passed immediately in isolation and the fresh full run above passed cleanly.

## Formal review round 5 remediation

Round 5 started from `90b9c45` (cumulative base remains `b8f2fe2`) and addressed five
binding audit findings without changing the root course documents or reviewer-owned
artifacts:

- production credential retrieval did not add the provider key to the audit sanitizer's
  live known-secret set;
- released R3 databases could expose already-persisted raw audit outbox payloads after an
  upgrade;
- a receipt update truncated its sole durable record before writing the replacement;
- the receipt cap was checked only after creating a rejected ID's sidecar; and
- the receipt/checkpoint namespace depended on the audit path's lexical parent, so a
  hardlink alias could lose the index and exceed the bounded rebuild window.

### Round-5 RED/GREEN evidence

1. The production composition and literal R3 migration tests were both behaviorally RED:
   the retrieved key survived in `audit_outbox.event_json`, and reopening returned the raw
   R3 event containing its provider secret and prompt body. GREEN shares one thread-safe
   `KnownSecretRegistry` across the lazy provider boundary, `CredentialService`,
   `AuditLogger`, and service export; it registers immediately after a valid keyring read
   and before the provider call. The same production test proves lazy retrieval, sanitized
   provider errors, redaction before SQLite serialization, redacted JSONL, and no key in
   pending events or the public task view. The R3 test proves startup removes the raw row
   without decoding or logging it, adds `sanitizer_version = 1`, and leaves neither raw
   string in the database, WAL/SHM artifacts, pending reads, or an SQLite dump during a
   simulated sink outage. The exact two-test GREEN slice passed 2/2; application,
   credential, and storage regressions then passed 127/127.
2. Seven receipt/cap/alias contracts were RED: zero-, one-, and 47-byte torn receipt
   updates lost the prior receipt; cap rejection and two racing writers created orphan
   files; default hardlink replay of a stream over 256 KiB required offline recovery; and
   a configured shared root was unsupported. GREEN passed all 7/7.
3. Receipts now keep the released JSON receipt region intact and use two fixed-size binary
   slots beyond it. Each slot carries magic, monotonically increasing generation, record
   offset/length, the 32-byte event ID, record digest, and a checksum. A commit writes only
   the inactive slot and `fsync`s it; loading chooses the newest valid slot and can still
   read an R4 JSON receipt. Reconciliation may replace a wholly torn first slot only when
   the corresponding complete JSONL record is present in the bounded suffix.
4. Receipt lookup first performs a descriptor-relative, no-create open. Under the audit
   stream lock, a missing distinct ID reserves capacity before any receipt file or shard
   directory is created. Existing IDs remain replayable at the cap; concurrent distinct
   writers produce exactly one JSONL record and one receipt.
5. The index base is now stable user state (or an explicitly configured root), never the
   audit file's lexical parent and never a production temp directory. Both the shared base
   and the native-file-identity leaf are created and validated with descriptor/handle-
   relative no-follow operations and owner-only permissions/DACLs. Hardlinks in different
   directories and a spawned process share the same identity namespace and replay a stream
   larger than 256 KiB without scanning or duplicating it. Tests inject one session-owned
   root and remove it only after all worker processes finish, avoiding production cleanup
   races and test pollution.

### Round-5 migration protocol

- Fresh outbox rows carry an explicit sanitizer protocol version, and pending reads select
  only that version. Startup enables SQLite `secure_delete` before inspecting the schema.
- A pre-version table is dropped and recreated without selecting or deserializing its
  payload columns; incompatible versioned rows are deleted. WAL is checkpointed with
  `TRUNCATE`, the database is vacuumed, and WAL is truncated again before startup returns.
- The migration completion marker is written only after physical purge succeeds. If
  exclusive checkpoint/VACUUM cannot complete, construction fails closed and the absent
  marker forces the next startup to retry byte purging rather than treating the schema-only
  migration as complete.

### Round-5 modified files

- Runtime: `src/pyquality/application.py`, `src/pyquality/security.py`,
  `src/pyquality/service.py`, and `src/pyquality/storage/sqlite.py`.
- Tests: `tests/conftest.py`, `tests/security/test_redaction.py`,
  `tests/unit/test_application.py`, `tests/unit/test_service.py`, and
  `tests/unit/test_storage.py`.

### Round-5 final verification

- `python -m pytest -q -rs -p no:cacheprovider --basetemp "$env:TEMP\\pyquality-task11-r5-persistent-root-full-final"`:
  526 collected; 517 passed, 9 skipped, zero failures in 40.8 seconds.
- The nine skips are explicit environment capabilities: one POSIX-directory-descriptor
  contract on Windows and eight unavailable symlink/link-privilege contracts (patch-tool,
  process-lease, three audit/policy link groups). No functional failure was converted to a
  skip.
- `python -m ruff check src tests examples`: all checks passed.
- `git diff --check`: exit 0; only the repository's existing LF/CRLF conversion warnings
  were printed.
- Five worktree-local pytest basetemp directories created by earlier runs retain DACLs for
  expired sandbox TokenOwners: `.pytest-task11-r5-affected-a`,
  `.pytest-task11-r5-affected-b`, `.pytest-task11-r5-security-a`,
  `.pytest-task11-r5-security-b`, and `.pytest-task11-r5-slices-final`. Exact-path
  `Remove-Item`, `takeown`, and `icacls` cleanup attempts were denied. They remain untracked
  environment residue, are excluded from the explicit staging list, and no temp path is
  part of the commit or cumulative package.
- Required commit subject: `fix: harden audit migration and sidecar identity`.
