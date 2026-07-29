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
