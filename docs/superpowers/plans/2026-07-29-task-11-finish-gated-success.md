# Task 11 Finish-Gated Success Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make successful verification a durable completion candidate and require an explicit, freshly verified `finish` action before terminal success, enabling the approved deterministic Task 11 demo.

**Architecture:** SQLite stores one bounded green candidate per task, transactionally replaced or cleared with lifecycle transitions. `AgentLoop` continues after a passing patch, exposes bounded green evidence to the next model context, and accepts `finish` only after digest freshness and a final passing verification.

**Tech Stack:** Python 3.12, Pydantic domain models, SQLite, pytest, Ruff.

## Global Constraints

- Follow `docs/superpowers/specs/2026-07-29-task-11-finish-gated-success-design.md` exactly.
- Preserve uncommitted Task 11 fixture/RED tests already created before the design pause.
- No production change without a literal failing test first.
- Green candidate data is bounded, typed, redacted, durable, and excluded from deterministic evidence when it contains timestamps or temporary paths.
- `finish` always performs final verification; stale, missing, or failing evidence cannot succeed.
- Preserve Task 8–10A lease, deadline, approval, recovery, accounting, redaction, and service lifecycle contracts.
- Root course documents remain untouched until implementation and review are clean.

---

### Task 1: Persist Green Completion Candidates

**Files:**
- Modify: `src/pyquality/domain/models.py` only if a typed candidate model is needed
- Modify: `src/pyquality/storage/sqlite.py`
- Modify: `tests/unit/test_storage.py`

**Interfaces:**
- Produces: `GreenCandidate` bounded fields and repository methods `save_green_candidate`, `green_candidate`, and `clear_green_candidate`, or equivalent exact typed names documented in the task report.

- [ ] Write storage RED tests for save/read/replace/clear, crash-reopen durability, bounded fields, task isolation, and transactional clearing on terminal transition.
- [ ] Run focused storage tests and capture failures caused by absent candidate persistence.
- [ ] Implement the minimal schema/model/repository API; no raw report output, source, prompts, or absolute paths.
- [ ] Rerun focused storage tests to GREEN and commit `feat: persist green completion candidates`.

### Task 2: Require Finish After Green Verification

**Files:**
- Modify: `src/pyquality/loop.py`
- Modify: `src/pyquality/context.py` if structured green evidence needs an existing context field
- Modify: `tests/loop/test_agent_loop.py`
- Modify: `tests/loop/test_approval_resume.py` only for recovery coverage

**Interfaces:**
- Consumes the Task 1 candidate API and existing pipeline/report/digest interfaces.
- Produces finish-gated `AgentLoop.run/resume/run_leased` behavior without public signature changes.

- [ ] Add a failing scripted-loop test: corrected patch passes, task remains RUNNING, next context states green/finish permitted, scripted `finish` is consumed, final verification passes, then `SUCCEEDED`.
- [ ] Add failing tests for finish without candidate, finish after a failing report, and final-verification failure; each returns bounded typed feedback and cannot succeed.
- [ ] Add deterministic repository-drift RED: mutate after candidate, `finish` clears/rejects candidate, and only a later quality run can establish a replacement.
- [ ] Implement minimal loop/context behavior. Passing action verification saves candidate and continues; `finish` checks deadline/lease/digest, runs final verification, persists result, and terminalizes only on pass.
- [ ] Rerun focused loop tests to GREEN and commit `feat: gate task success on finish`.

### Task 3: Recovery, Accounting, and Audit Regression

**Files:**
- Modify: `tests/loop/test_agent_loop.py`
- Modify: `tests/loop/test_approval_resume.py`
- Modify storage/loop production only if a new failing recovery test proves a gap

**Interfaces:**
- Consumes durable candidate and finish-gated loop semantics.
- Preserves existing iteration, lease, approval, deadline, audit, and terminal idempotency contracts.

- [ ] Add crash/reopen RED after green candidate and prove `resume()` consumes a later `finish` and succeeds.
- [ ] Add regression tests for separate corrected-patch/finish iterations, provider retry accounting, deadline before finish/final verifier, lease loss, WAITING_APPROVAL, terminal resume idempotency, and redacted candidate/finish audit events.
- [ ] Implement only gaps demonstrated by RED; rerun affected loop/storage/security tests to GREEN.
- [ ] Commit `fix: recover finish-gated completion evidence` if production changes are needed; otherwise record a test-only regression commit in the report.

### Task 4: Complete the Deterministic Mechanism Demo

**Files:**
- Preserve/create: `examples/broken_calculator/calculator.py`
- Preserve/create: `examples/broken_calculator/tests/test_calculator.py`
- Preserve/create: `tests/e2e/test_demo.py`
- Create/modify: `tests/e2e/test_mechanism_contract.py`
- Create: `src/pyquality/demo.py`
- Modify: `src/pyquality/cli.py`
- Modify packaging only if required for fixture inclusion

**Interfaces:**
- Produces `run_demo(work_dir: Path) -> DemoReport` and `pyquality demo --json`.

- [ ] Preserve the already captured import-contract RED and add isolation/CLI/double-run RED tests from the Task 11 brief.
- [ ] Implement the exact four-action scenario through real mechanisms: denied traversal, incomplete patch, corrected patch after assertion feedback, `finish`.
- [ ] Prove denied dispatch count zero, feedback provenance, changed patch digests/fingerprints, stable normalized double-run evidence, no network/credential access, and final `SUCCEEDED`.
- [ ] Run `tests/e2e`, affected CLI/service/loop/storage/security tests, pristine full, Ruff, and cumulative diff checks.
- [ ] Commit `feat: add deterministic harness mechanism demo`.

## Final Task 11 Review Package

Update `.superpowers/sdd/2026-07-29-task-11-demo/task-11-report.md` and ledger with every RED/GREEN command/result, candidate persistence and digest reasoning, exact commits, evidence provenance, full verification counts, and self-review. Generate one frozen cumulative package from the finish-gated plan execution base to final HEAD. Root course documents remain untouched until independent Task 11 review is clean.
