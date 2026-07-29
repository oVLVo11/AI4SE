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
