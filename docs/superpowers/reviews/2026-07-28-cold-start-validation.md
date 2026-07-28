# Cold-start Validation Record — 2026-07-28

## Dispatch Metadata

- Agent identity: `/root/task0_docs_coldstart/coldstart_validator`
- Model: `gpt-5.6-sol`
- History mode: `fork_turns="none"`
- Inputs supplied:
  - `C:\Users\12116\Desktop\AI4SE\.worktrees\pyquality-harness\SPEC.md`
  - `C:\Users\12116\Desktop\AI4SE\.worktrees\pyquality-harness\PLAN.md`
- Exact instruction supplied:

> Dry-run the reasoning for Task 1 and one risk-heavy task without writing implementation code. Stop at uncertainty rather than guess. Report every question, divergent interpretation, and expected file/interface mismatch.

No implementation files were supplied to the agent.

## Verbatim Validator Result

Cold-start validation completed without implementation edits. I selected Task 8 as the risk-heavy task.

## Task 1 findings

Questions that block confident implementation:

- What are the exact fields and invariants for `QualityReport`, `TaskResult`, `PolicyOutcome`, `ToolResult`, `ApprovalDecision`, and `AuditEvent`? The plan names them but only specifies shapes for `Action`, `Finding`, and `TaskStatus`.
- Is `PolicyOutcome` an enum (`allow`, `require_approval`, `deny`) or a structured decision model? Task 3 introduces a separate `PolicyDecision`.
- Should `Action` remain one model with an untyped `arguments: dict`, or be a discriminated union with per-action argument schemas? The current shape accepts semantically invalid combinations such as `{"kind":"read_file","arguments":{"patch":"..."}}`.
- Are unknown fields forbidden on every public Pydantic model, or only on `Settings`?
- Must `Finding.path` be repository-relative, canonical absolute, or source-dependent?
- What limits apply to `summary`, `evidence`, `group_key`, `rationale`, and action argument values?
- Is a `line` without a `path` valid?
- What exact fields determine whether a `QualityReport` represents full-suite pytest and Ruff success?
- Does `TaskResult.iterations` count LLM responses, valid actions, executed actions, or persisted iteration rows?
- What configuration tables and keys are valid? Only the invalid `[security] allow_shell` example is concrete.
- What happens if both `pyproject.toml` and `pyquality.toml` exist in the repository?
- Is repository precedence `pyproject.toml` then `pyquality.toml`, the reverse, or a conflict error?
- What format does `user_file` use, and is it optional because absence is normal or because a platform-default user file is resolved elsewhere?
- What are the exact secure defaults for timeouts, exclusions, output budgets, per-finding budgets, and safe pytest/Ruff arguments?
- Which pytest/Ruff arguments are allowed or denied? “Safe schemas” is not sufficient to implement validation without guessing.
- May repository configuration reduce security-related limits and exclusions, or are some settings user-only?
- How are TOML parse errors, unreadable files, wrong value types, and conflicting settings surfaced through `ConfigError`?
- Should missing `repo_root`, a non-directory root, or symlinked root fail in Task 1?
- Does Python 3.12-only mean metadata must reject 3.13+, or is `>=3.12` intentional?
- Is editable installation truly part of implementation, given dependency installation may require network and is not a source-code operation?

Divergent interpretations:

- “Typed action” can mean a typed outer envelope or fully typed per-tool payloads. The supplied `dict[str, JsonValue]` implements only the former.
- “Unknown fields fail” could apply only within known configuration sections, or also mean every unrecognized top-level/table key fails.
- “Defaults → user → repository” suggests repository settings override user settings, while the security text says repository configuration cannot weaken controls. A field-by-field monotonic merge may be intended but is not defined.
- `pyproject.toml` and `pyquality.toml` could be two equivalent repository sources, complementary sources, or mutually exclusive sources.
- The specification’s human-facing categories (“syntax error”, “Ruff violation”, etc.) differ from the plan’s serialized values (`syntax`, `ruff`). This likely means display labels versus stable wire values, but that mapping is unstated.

Expected Task 1 file/interface mismatches:

- `pyproject.toml` declares `pyquality.cli:main`, but `src/pyquality/cli.py` is not created until Task 10. Installation may succeed, but invoking or validating the entry point before Task 10 will fail.
- Task 1 promises no `Any` at public boundaries while `Action.arguments` is structurally untyped beyond JSON values.
- Task 3 consumes `PolicyOutcome` but produces `PolicyDecision`; the relationship is unspecified.
- Task 5 needs `QualityReport` semantics that Task 1 does not define.
- Task 6 needs iteration-history and deadline-compatible types not included among Task 1’s specified shapes.
- Task 8’s tests require meaningful `TaskResult.status` and `.iterations`, but Task 1 gives no `TaskResult` contract.
- The architecture names entities such as `Iteration`, `Approval`, and `Decision`, but Task 1’s produced model list omits them; Task 2 therefore has no agreed typed persistence inputs.
- No lockfile is planned, so the broad dependency ranges do not guarantee reproducible cold-start installation.

## Task 8 findings

Questions that block confident implementation:

- What are the complete legal states and transitions? There is no initial `CREATED`, `READY`, `VERIFYING`, or internal recovery state.
- What exactly is an iteration? Does a denied action, invalid model response, format-repair response, read action, approval pause, or resumed approved execution increment it?
- Do the two format-repair attempts mean two retries after the initial invalid response, or two total attempts?
- Do format-repair calls consume the eight-round LLM budget?
- Do provider timeout retries consume rounds, and where is their retry policy implemented?
- Which actions trigger verification? The specification says after a code-changing action, while `run_quality` and `finish` also explicitly request verification.
- After an allowed `apply_patch`, must quality run immediately even if the model intended several patches?
- If `finish` runs verification and fails, does the same iteration contain both finish and findings, or is a new iteration created?
- If `finish` succeeds, does it count as one of the asserted three iterations?
- How does the loop obtain changed paths and relevant content-change digests from `ToolResult`?
- How does it distinguish relevant from unrelated file changes for stall detection?
- What happens when revalidation changes an approved action from approval-required to denied, allowed, or a differently normalized action?
- What does “canonicalized and checked again” mean for an `apply_patch`, which is content rather than a path-bearing action envelope?
- What canonical JSON algorithm defines the normalized action digest?
- What happens if the repository changes externally while waiting for approval?
- Does resume reacquire or retain the repository lease? Holding a lease across a human wait can indefinitely block later tasks; releasing it permits repository drift.
- Who releases leases on `WAITING_APPROVAL`, `BLOCKED`, crash, deadline expiry, and internal failure?
- Can an approval decision be changed, repeated, or made after task termination?
- What exception/result should duplicate approval decisions produce?
- What is `pending_approval(task_id)`? Tests use it, but Task 8 does not list it as a produced interface.
- After rejection, does resume immediately call the LLM, and does rejection consume a round?
- What exact structured feedback represents policy denial versus human rejection?
- What should happen if the LLM is exhausted after a rejection?
- How are wall-clock deadlines checked during a verifier run or provider request?
- Which injected clock and transaction interfaces should be used?
- Which failures map to `BLOCKED` versus `FAILED` when validators, storage, policy, or dispatch raise?
- How are audit events redacted in Task 8 when centralized redaction and `AuditLogger` are deferred to Task 9?
- What does “persist before and after model calls” store, given the specification prohibits complete prompts and responses by default?
- How can exactly-once filesystem dispatch be guaranteed across a crash? Marking approval executed before dispatch risks losing the action; marking it after dispatch risks replay.
- Is `resume()` idempotent once a task is terminal, and what exact `TaskResult` must it return?
- If `resume()` is called twice after approved execution, should the second call continue subsequent model work or merely prove the approved action is not replayed? The sample does not constrain other behavior.
- What should happen if a pending approval has expired because the task deadline elapsed?

Divergent interpretations:

- “Persist before every externally observable transition” could mean an intent/outbox record before an effect, or merely committing current state before calling the effect. These provide different crash guarantees.
- “Executed transactionally” cannot literally include a filesystem patch and SQLite commit in one transaction. The design must choose at-least-once, at-most-once, idempotent dispatch, or compensation.
- A model round could be each provider call or each valid action. This changes budgets, format repair, and the sample iteration count.
- `WAITING_APPROVAL` could retain the active repository modification lease or release it while storing a repository snapshot/digest.
- “No model call after a terminal decision” could mean after the decision is computed in memory or only after it is durably persisted.
- A denied policy action may create an iteration with feedback, while an approval-required action may be the same iteration paused or a transition between iterations.
- “All stop states” could require Task 8 to interpret validator categories directly or delegate entirely to `ProgressTracker`.

Expected Task 8 file/interface mismatches:

- Task 8 says it consumes “all core protocols from Tasks 2–7,” but those tasks do not define a single application-facing protocol bundle or constructor signature for `AgentLoop`.
- Task 2’s listed repository methods lack approval lookup, decision update, executed marking, transition journaling, compare-and-set status changes, and atomic recovery APIs required by Task 8.
- Task 2’s data model stores one `action_json` per iteration, which is awkward for format-repair attempts and pre/post model-call persistence.
- Task 3’s `revalidate(decision)` does not accept the current action or repository snapshot, yet Task 8 requires action-bound revalidation immediately before dispatch.
- Task 4’s `ToolResult` contract is unspecified, so Task 8 cannot reliably obtain changed files, content digests, or whether an action was code-changing.
- Task 5’s `QualityPipeline.run(changed_paths)` requires changed paths that no prior interface explicitly guarantees.
- Task 6’s `ProgressTracker.decide(history, round_limit, deadline, now)` lacks explicit relevant-file-content-change input even though the stall rule depends on it.
- Task 7’s `ActionParser.parse()` exposes one parse attempt, but the ownership and persistence of repair prompts/responses are unspecified.
- Task 7’s `LLMClient.complete()` has no visible timeout/retry metadata interface needed for bounded provider retry decisions and auditing.
- Task 9, which follows Task 8, owns `AuditLogger` and centralized redaction even though Task 8 requires durable audit-safe transition records.
- `pending_approval()` appears in tests but not in Task 8’s declared output interfaces.
- The architecture says the application service owns adapters, but Task 8 has no defined dependency-injection boundary for repository, policy, dispatcher, pipeline, context builder, parser, LLM, progress tracker, clock, or audit sink.
- The example `loop_fixture` signatures are mutually different and do not establish a realizable fixture contract.

Recommended narrow plan corrections before implementation:

- Add explicit Pydantic shapes and invariants for every Task 1-produced type.
- Replace `Action.arguments` with a discriminated action union or define per-kind validators.
- Publish the complete configuration schema, defaults, repository-source precedence, and safe argument grammar.
- Define iteration/round accounting and a state-transition table.
- Add repository APIs for compare-and-set transitions, approval decision/execution state, transition intents, and recovery snapshots.
- Explicitly choose crash semantics for non-transactional filesystem effects.
- Define normalized action serialization and repository-drift handling across approval waits.
- Extend `ToolResult` with changed paths/content digests and align `ProgressTracker` inputs with the relevant-change stall rule.
- Move the minimal redaction/audit abstraction before Task 8 or state that Task 8 uses an injected audit sink implemented later.
- Add `pending_approval()` to the formal interface or remove its use from the tests.

