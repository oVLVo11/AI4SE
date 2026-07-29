# PyQuality Harness Design Specification

**Status:** Approved design  
**Date:** 2026-07-28  
**Scope:** A local-first coding agent harness for Python quality-feedback loops

## 1. Problem Statement

Python developers can ask an LLM to change code, but a useful coding agent needs deterministic engineering around the model: constrained tools, objective verification, safe execution, selective context, recoverable state, and explicit stopping rules. PyQuality Harness accepts a local Python repository and a natural-language task, lets an LLM propose typed actions, and uses pytest and Ruff results to drive bounded self-correction.

The target user is an individual Python developer who wants an auditable local coding assistant rather than an unconstrained shell agent. The primary contribution is the feedback loop: it parses failures, classifies them, extracts minimal relevant evidence, detects progress or repetition, and constructs the next correction context in deterministic code.

The project is useful because it turns one-shot model output into a repeatable quality-control process while preserving human ownership over risky changes.

## 2. Goals and Non-goals

### 2.1 Goals

- Implement the complete agent loop without an agent orchestration framework.
- Support one local Python repository and one task per run.
- Verify changes with pytest and Ruff.
- Convert raw verifier output into structured, prioritized, compact feedback.
- Detect success, blocked execution, repeated failure, invalid model output, and exhausted budgets.
- Keep every core mechanism testable with a scripted mock LLM and no network.
- Confine tools to the selected repository and require approval for defined risky actions.
- Preserve task state and retrieve only relevant memory.
- Provide a local WebUI and an isolated public mock demonstration.
- Store real LLM credentials outside the repository using the operating-system credential store.

### 2.2 Non-goals

- Multiple agents, remote repository cloning, or languages other than Python.
- Arbitrary shell access, automatic Git commits or pushes, or automated publishing.
- A general validator plugin marketplace.
- Vector memory or semantic retrieval.
- A container-grade security sandbox for arbitrary hostile code.
- Autonomous dependency installation.

## 3. User Stories

1. As a Python developer, I want to give the harness a local repository and a change request so that it can attempt a bounded, test-driven repair.
2. As a Python developer, I want pytest and Ruff failures reduced to relevant, structured evidence so that correction rounds do not drown in terminal output.
3. As a cautious user, I want risky actions paused with a concrete impact summary so that I retain control over consequential changes.
4. As a user returning after interruption, I want an unfinished task to resume from persisted state without replaying an unapproved action.
5. As a maintainer, I want all harness mechanisms exercised with a mock LLM so that tests are deterministic, offline, and independent of model behavior.
6. As an evaluator, I want a repeatable demonstration of guardrail rejection, failed repair, feedback-driven changed action, and eventual success.
7. As a user, I want to add, update, inspect the status of, and clear my provider credential without exposing its value.
8. As a reviewer, I want an exportable redacted audit report so that I can inspect why a task stopped and what evidence drove each decision.

Each story is independently testable and can be delivered without requiring the excluded multi-agent or remote-execution features.

## 4. Functional Specification

### 4.1 Task Lifecycle and Agent Loop

**Input:** A canonical local repository path, a natural-language task, and optional safe configuration overrides.

**Behavior:**

1. Validate the repository, configuration, verifier availability, credential status, and concurrency rules.
2. Restore an existing task or create a new task with a default budget of eight LLM rounds plus a wall-clock deadline.
3. Build a bounded context containing the task, relevant project decisions, recent iterations, unresolved findings, and required file excerpts.
4. Request exactly one typed action from `LLMClient`.
5. Parse and validate the action, evaluate it through `PolicyEngine`, and dispatch it only if permitted.
6. After a code-changing action, run the quality pipeline and compose structured feedback for the next round.
7. Persist state before every externally observable transition and evaluate stopping rules.

**Output:** A terminal task status, iteration timeline, verification summary, changed-file list, and redacted audit report.

**Boundary conditions:** Only one active task may modify a repository at a time. Different repositories may run concurrently up to a default global limit of two, configurable down to one or up to four. A declaration of completion is not success unless the full pytest and Ruff checks pass.

**Errors:** Invalid actions receive at most two format-repair attempts. Provider timeouts retry within a small bounded policy. Permission, configuration, and infrastructure failures become explicit terminal or waiting states.

### 4.2 Typed Tools

The LLM may request only:

- `read_file(path, start_line?, end_line?)`
- `search_text(pattern, paths?)`
- `list_files(path?, limit?)`
- `apply_patch(patch)`
- `run_quality(scope?)`
- `finish(summary)`

All paths are canonicalized before use. Reads and search results are byte-limited and marked when truncated. `.git`, virtual environments, caches, and sensitive paths are excluded. `apply_patch` requires contextual hunks and cannot overwrite an entire repository. `run_quality` invokes only harness-defined commands.

### 4.3 Quality Pipeline

After a code change, validators run in this order:

1. Directly run a changed test file when the patch itself changes a path matching `tests/test_*.py` or `test_*.py`; otherwise skip the targeted phase.
2. Full configured pytest suite.
3. Ruff check.

Passing a relevant subset never substitutes for the full-suite success gate. A command timeout is a finding, not a pass.

Each raw result is parsed into a `Finding` with source, category, severity, path, line, summary, compact evidence, and root-cause grouping key. Required categories are:

- syntax error;
- import or collection error;
- assertion failure;
- runtime exception;
- Ruff violation;
- timeout;
- missing tool or dependency;
- unknown infrastructure error.

The feedback composer prioritizes infrastructure, syntax, and import failures before assertions, and assertions before lint findings. It groups duplicate root causes, removes repeated stack frames, applies total and per-finding byte budgets, and reports every omission or truncation.

### 4.4 Progress and Stopping

Each quality result receives a stable failure fingerprint derived from normalized finding categories, locations, and root-cause keys; volatile values such as temporary paths and timings are excluded.

Terminal and waiting states are:

- `SUCCEEDED`: full pytest and Ruff both pass.
- `WAITING_APPROVAL`: an approvable action awaits a human decision.
- `STALLED`: the same failure fingerprint occurs twice consecutively with no relevant file-content change.
- `BUDGET_EXHAUSTED`: the round or wall-clock budget is consumed.
- `BLOCKED`: a missing dependency, invalid environment, configuration error, or permission problem cannot be repaired through allowed tools.
- `FAILED`: the model response remains invalid after two format-repair attempts, or an unrecoverable internal error occurs.

Changing unrelated files does not count as progress. A rejected action is fed back as a policy result and does not consume an execution approval implicitly.

### 4.5 Governance and Human Approval

Policies produce one of three outcomes:

- `ALLOW`: repository-contained reads, searches, ordinary contextual patches, and quality runs.
- `REQUIRE_APPROVAL`: repository file deletion, a patch touching more than 10 files or changing more than 300 total lines, or changes to dependency declarations and CI configuration.
- `DENY`: repository-boundary escape, sensitive-file access, arbitrary network or shell commands, Git push, publication, privilege escalation, and destructive system actions.

An approval record includes the normalized action, matched policy, affected files, risk explanation, decision, and timestamps. Approval is single-use. After approval, the action is canonicalized and checked again immediately before dispatch. Rejection becomes structured model feedback. There is no permanent bypass rule.

### 4.6 Memory and Context Selection

SQLite stores task and audit state. Context selection retrieves only:

- the current task;
- at most the two most recent iterations;
- unresolved high-priority findings;
- excerpts of files implicated by the current action or findings;
- project decisions whose verifier or file scope matches the current problem.

Raw terminal output is retained locally for audit within configured storage limits but is never automatically inserted wholesale into the model context. Resume begins at the last committed state and never replays an action that was pending approval.

### 4.7 Configuration

`pyquality.toml` may configure test locations, pytest and Ruff arguments from safe schemas, exclusions, output limits, iteration limits, and timeouts. Configuration merges in this order: built-in secure defaults, user configuration, then repository configuration.

Repository configuration cannot widen path boundaries, enable arbitrary shell execution, disable credential redaction, or convert a denied action into an allowed action. Unknown fields and invalid values fail before task execution.

### 4.8 Interfaces

The CLI provides task execution, server startup, mock demonstration, configuration inspection, and credential management.

The server-rendered WebUI contains:

- a task creation page;
- a task timeline and status page;
- an approval page;
- a provider and credential-status settings page.

The public demonstration accepts only bundled examples and mock LLM scenarios. It cannot accept an arbitrary filesystem path or real API key.

## 5. Domain and Mechanism Design

### 5.1 Coding-domain Tools

The minimum useful coding actions are bounded file discovery, targeted reading, contextual patching, and verifier execution. Arbitrary shell is deliberately excluded because pytest and Ruff can be exposed through typed operations.

### 5.2 Objective Feedback Signals

Pytest supplies behavioral and runtime evidence. Ruff supplies deterministic static-quality evidence. Exit status, parsed diagnostics, timeouts, and tool availability are evaluated by code. The LLM cannot declare these checks successful.

### 5.3 Dangerous Actions

Repository escape, secrets access, network effects, publishing, privilege changes, and destructive system commands are always denied. Repository deletion, broad patches, dependency changes, and CI changes require explicit approval because they may be legitimate but have elevated impact.

### 5.4 Memory Needs

The harness remembers task history, project-level decisions, current findings, approvals, and failure fingerprints. It does not treat entire conversations as memory. Deterministic scope matching and recency rules select relevant records.

### 5.5 Primary Contribution

The feedback loop is the deep dimension. Its implementation includes validator orchestration, output parsers, failure taxonomy, evidence budgets, root-cause grouping, stable fingerprints, progress detection, and stopping rules. These functions accept ordinary values and process results, so each remains unit-testable after replacing the real LLM with a mock.

## 6. Architecture

### 6.1 Components

- `AgentLoop`: lifecycle and state-machine owner.
- `LLMClient`: injectable single-response model boundary with scripted mock and OpenAI-compatible implementations.
- `ActionParser`: schema validation and bounded format repair.
- `ContextBuilder`: deterministic memory and source-excerpt selection.
- `PolicyEngine`: action classification and approval policy.
- `ToolDispatcher`: the only component permitted to perform tool effects.
- `QualityPipeline`: pytest and Ruff orchestration.
- `ResultParser`: raw output to normalized findings.
- `FeedbackComposer`: prioritization, grouping, and evidence budgeting.
- `ProgressTracker`: fingerprints and stop decisions.
- `TaskRepository`: SQLite persistence and transactional transitions.
- `WebApp` and `CLI`: thin adapters over the core application service.

The core package does not import FastAPI. UI code depends on the application service, which depends on interfaces for model, storage, process execution, time, and credentials.

### 6.2 Data Flow

`User request → preflight → context builder → LLM client → action parser → policy engine → dispatcher → quality pipeline → result parser → feedback composer → persistence → next iteration or stop`

An approval outcome rejoins the flow at policy evaluation. Every effect is reached only through the policy engine and dispatcher.

### 6.3 External Dependencies

- OpenAI-compatible HTTP response API for optional real-model operation.
- pytest and Ruff executables in the selected project environment.
- Operating-system credential service through `keyring`.
- SQLite from the Python standard library.
- FastAPI, Jinja2, and HTMX for the WebUI.

No external dependency supplies an agent loop, tool router, governance hook, memory subsystem, or feedback loop.

## 7. Data Model

### 7.1 Entities

- `Project(id, canonical_path, display_name, detected_config, created_at, updated_at)`
- `Task(id, project_id, request, status, round_limit, deadline, created_at, updated_at, finished_at)`
- `Iteration(id, task_id, sequence, context_digest, action_json, policy_outcome, tool_result_digest, fingerprint, created_at)`
- `Finding(id, iteration_id, source, category, severity, path, line, summary, evidence, group_key)`
- `Approval(id, task_id, iteration_id, action_json, policy_rule, impact_json, decision, decided_at, executed_at)`
- `Decision(id, project_id, scope_type, scope_value, content, source, created_at, updated_at)`
- `AuditEvent(id, task_id, iteration_id, component, event_type, metadata_json, created_at)`

### 7.2 Constraints

- Iteration sequence is unique within a task.
- Only one nonterminal task may hold a repository modification lease.
- Approval execution requires an approved, unexecuted record whose normalized action still matches.
- Findings belong to exactly one iteration.
- Database fields never store provider secrets, raw authorization headers, or unredacted sensitive-file contents.

SQLite lives in the platform-specific user application-data directory. Tests use isolated temporary databases.

## 8. Security and Credential Design

### 8.1 Threat Model

Threats include malicious or mistaken model actions, path traversal and symlink escape, prompt content requesting secrets, sensitive data in tool output, command injection through configuration, API keys in source or logs, stale approval replay, concurrent repository corruption, and hostile code executed by pytest.

### 8.2 Controls

- Canonical path and symlink-boundary checks occur at policy time and immediately before effects.
- Sensitive filename and directory rules deny reads even inside the repository.
- No arbitrary shell tool exists; subprocess arguments are constructed from validated schemas without shell interpolation.
- Tool output, logs, exceptions, audit export, and UI pass through centralized redaction.
- Repository modification leases prevent concurrent writers.
- Approval is action-bound, single-use, and revalidated.
- pytest and Ruff use timeouts and process-output limits.
- The UI binds to loopback by default and uses per-session CSRF protection for mutations.

Running repository tests executes project code with the harness process's operating-system privileges. This remains a documented limitation: users must run untrusted repositories inside an external VM or container. The harness's repository boundary does not claim to be an OS sandbox.

### 8.3 Credential Lifecycle

The real provider key is stored through the operating-system credential store using `keyring`. First use requests hidden input. Commands support set, status, update, and clear; status never reveals the value. The key is loaded only immediately before a provider request and is never placed in task context or persistence.

An environment variable is an explicit compatibility fallback with documented process-visibility and plaintext risks. The application does not create `.env`. If the user chooses `.env` loading, startup verifies that the file is excluded by Git and warns otherwise.

The public mock deployment never accepts or stores provider credentials.

Task 9A makes the credential boundary closed under its 4,096-byte UTF-8 limit: provider callback text above that boundary is rejected before return, and numeric-looking credentials whose canonical equivalence class cannot remain within the accepted domain are rejected at `set`. Accepted integer, fixed-decimal, and exponent spellings share one bounded identity; nonnumeric credential text remains exact.

On Windows, a new audit file is created with a protected owner-only DACL in the final `NtCreateFile` call, using the process token's `TokenOwner`. An existing audit file is opened exclusively and accepted only when its retained handle reports that exact owner-only protected DACL; otherwise logging fails with a typed sanitized error and does not mutate the file or its DACL.

## 9. Technology, Distribution, and Deployment

- Python 3.12 for the harness and packaging.
- Pydantic for typed boundary schemas.
- FastAPI with Jinja2 and HTMX for a small server-rendered UI.
- SQLite for local durable state.
- pytest for tests and Ruff for linting.
- PyPI package as the primary local distribution, exposing `pyquality`.
- OCI/Docker image for the isolated mock demonstration.
- Render or an equivalent low-cost host for the public demonstration.

The required entry-point families are `pyquality run`, `pyquality serve`, `pyquality demo`, and `pyquality credential`. The implementation plan will assign flags and subcommands within these fixed families without expanding product scope.

CI includes both GitHub Actions for push/PR verification and the course-mandated `.gitlab-ci.yml` with a job named `unit-test`. Pipelines run unit and component tests, Ruff, package build, and Docker build. Publishing credentials are never required for ordinary pull-request CI.

## 10. Error Handling and Observability

User errors such as invalid paths, malformed configuration, or missing verifier tools fail during preflight with actionable messages. Recoverable provider timeouts and action-format errors use bounded retry rules. Security violations, boundary escapes, credential-backend failures, and database failures stop safely and create audit events.

JSON Lines logs contain task ID, iteration, component, event type, duration, and outcome. They exclude API keys, authorization headers, complete prompts, complete model responses, and source bodies by default. A task can export a redacted audit report.

The UI summarizes LLM call count, verifier duration, finding counts by category, repeated-failure count, budget consumption, and final stop reason. No external observability service is required in the first version.

## 11. Testing Strategy and Mechanism Demonstration

### 11.1 Unit Tests

Unit tests cover action parsing, path confinement, policy outcomes, approval replay prevention, pytest and Ruff parsing, category priority, evidence truncation, root-cause grouping, stable fingerprints, progress detection, all stop states, configuration merging, memory selection, and redaction.

### 11.2 Component Tests

Temporary Python repositories and real local pytest/Ruff processes verify that patches change quality results as expected. Process execution is time- and output-bounded. Network access and a real LLM are unnecessary.

### 11.3 Loop Tests

A scripted mock LLM emits predetermined actions and records received contexts. Tests assert dispatch order, feedback content, waiting and resume behavior, changed actions after feedback, and terminal outcomes.

### 11.4 Web Tests

Tests cover task creation, timeline rendering, approval and rejection, credential status without value disclosure, CSRF checks, and the mock demonstration.

### 11.5 Deterministic Demonstration

One command runs a bundled scenario:

1. A mock action attempts an out-of-repository write; policy denies it and the dispatcher is not invoked.
2. A mock action applies a patch that leaves a pytest failure.
3. The pipeline classifies and compresses the failure and feeds it to the next model context.
4. The mock LLM emits a different patch in response.
5. Full pytest and Ruff pass.
6. The audit report proves that fingerprints changed and progress was detected.

## 12. Acceptance Criteria

- A clean supported environment can install the package and start its CLI and local WebUI using documented commands.
- The harness implements its own model/action/tool/feedback/stopping loop and imports no high-level agent runner.
- All core mechanisms pass deterministic tests with the mock LLM and no network.
- A bundled Python repair scenario ends with full pytest and Ruff passing.
- Parsed findings are categorized, deduplicated, prioritized, and bounded before model injection.
- Repeated identical failure with no relevant file change reaches `STALLED` exactly as specified.
- Round and time exhaustion reach `BUDGET_EXHAUSTED` without further model calls.
- A boundary-escape action is denied before tool execution.
- An approvable action pauses, persists, and executes at most once after explicit approval and revalidation.
- No credential value appears in repository files, SQLite, normal logs, audit export, or WebUI responses.
- Task resume does not replay a pending or previously executed approval.
- `pytest` is the documented one-command test entry point and all tests pass.
- The PyPI distribution and Docker demonstration image build in CI.
- `.gitlab-ci.yml` contains a `unit-test` job, and GitHub Actions runs verification on pushes and pull requests.
- A public WebUI URL completes the bundled isolated mock demonstration without a key.

## 13. Risks and Resolutions

- **pytest runs repository code:** Document that the path guard is not an OS sandbox and recommend an external VM/container for untrusted repositories.
- **pytest output varies by version:** Normalize known formats, retain an unknown category, and test against representative fixtures.
- **Relevant-test selection can miss regressions:** Always require the full test suite before success.
- **Ruff may be absent from the target environment:** Treat missing tools as preflight/blocking errors with installation guidance; never install autonomously.
- **Keyring availability differs by platform:** Detect backend availability before storing a key and offer the explicitly warned environment fallback.
- **Public hosting cannot access a user's local path:** Separate local real mode from a hosted mock-only demonstration.
- **SQLite process concurrency:** Use a single application worker initially, transactional writes, and repository leases.
- **Course materials mention both GitHub Actions and `.gitlab-ci.yml`:** Provide both configurations so neither delivery expectation is omitted.
- **Broad patches are hard to classify:** Require approval when a patch touches more than 10 files or changes more than 300 total lines; count additions and deletions before applying the patch.
## 14. Cold-start Contract Clarifications

These clarifications resolve the documented cold-start review without changing product scope.

### 14.1 Public Models and Configuration

Task 1 defines public Pydantic models with `extra="forbid"`: `Action`, `Finding`, `QualityReport`, `TaskResult`, `PolicyOutcome`, `PolicyDecision`, `ToolResult`, `ApprovalDecision`, and `AuditEvent`. `PolicyOutcome` is the enum `ALLOW | REQUIRE_APPROVAL | DENY`; `PolicyDecision` contains that outcome, the matched rule, an impact summary, and a normalized action digest. `ApprovalDecision` is `APPROVE | REJECT`.

`Action` is a discriminated union by `kind`, with per-tool argument models; action-specific keys are forbidden. Every action includes a bounded non-empty rationale. `Finding.path` is repository-relative POSIX text or null; `line` is null unless path is present. `summary`, `evidence`, `group_key`, rationale, patterns, and arguments are byte-bounded by settings. `QualityReport` records targeted-phase status, full-pytest status, Ruff status, findings, commands, timeouts, and changed paths; success requires a passing full pytest suite and Ruff. `TaskResult` records task ID, terminal or waiting status, iteration count, verification summary, changed paths, and audit location. An iteration is one persisted model-response/action cycle; an invalid response and each repair response are cycles, while provider transport retries are not.

`pyquality.toml` is the only repository configuration source. `pyproject.toml` is packaging metadata and is never a second configuration source. Configuration merges built-in secure defaults, optional user file, then `pyquality.toml`; repository values may narrow limits or add exclusions but cannot weaken boundaries, redaction, denied actions, or safe argument grammar. The user file is optional and explicitly supplied. Missing or non-directory repository roots, canonical-root escape, unreadable or malformed TOML, unknown keys, wrong types, and conflicting values raise `ConfigError` during preflight. Python metadata is `>=3.12`; 3.13 and newer remain supported.

Secure defaults are: round limit 8, global concurrency 2, subprocess timeout 60 seconds, provider timeout 30 seconds, provider retries 2, total feedback 32 KiB, per-finding evidence 4 KiB, tool output 64 KiB, read/search result 64 KiB, and source excerpt 8 KiB. Safe pytest arguments are only paths beneath the repository plus `-q`, `-v`, `-x`, and `-k <expression>`; safe Ruff arguments are only repository-relative paths plus `--select <codes>`, `--ignore <codes>`, and `--output-format text`. No setting may add shell syntax, command executables, or arbitrary pytest/Ruff flags.

All public byte limits measure UTF-8 encoded bytes and are enforced before persistence or model dispatch. The settings are `max_rationale_bytes=4_096`, `max_finding_summary_bytes=1_024`, `max_finding_evidence_bytes=4_096`, `max_group_key_bytes=512`, `max_action_arguments_bytes=65_536`, `max_tool_output_bytes=65_536`, `max_tool_metadata_bytes=16_384`, `max_config_pattern_bytes=1_024`, and `max_config_patterns=128`; `source_excerpt_bytes=8_192` and `feedback_total_bytes=32_768` name the source-excerpt and total-feedback caps. Tool-result output/evidence uses `max_tool_output_bytes`; serialized action arguments, including patch JSON, use `max_action_arguments_bytes`; individual path strings use `max_config_pattern_bytes` and normalized repository-relative validation. Repository configuration may only lower these byte/count caps.

### 14.2 Loop, Approval, and Recovery Contract

The legal persisted task states are `CREATED`, `RUNNING`, `WAITING_APPROVAL`, `SUCCEEDED`, `STALLED`, `BUDGET_EXHAUSTED`, `BLOCKED`, and `FAILED`. `CREATED -> RUNNING`; `RUNNING -> WAITING_APPROVAL` for an approvable action; `WAITING_APPROVAL -> RUNNING` after either decision; and only `RUNNING` reaches terminal states. Terminal `resume()` is idempotent and returns the saved `TaskResult`. A deadline checked before each model call, dispatch, and verifier transition wins over further work; a running subprocess is governed by its timeout.

A model round is every provider response, including invalid-format and format-repair responses; the initial invalid response plus at most two repair responses are permitted. Provider transport retries happen within one round and use the provider retry limit. Rejected and denied actions produce structured feedback and consume the response/action cycle that created them. A code-changing `apply_patch` immediately runs the quality pipeline. `run_quality` runs it explicitly. `finish` requests the same full verification; a failed finish produces feedback and remains running. The sample three iterations therefore count denied/read-independent actions only when they are model responses, and count bad patch, corrected patch, and finish as three responses in its stated scenario.

`ToolResult` contains effect kind, code_changed, repository-relative changed paths, before/after content digests for changed files, truncation, normalized result metadata, and optional bounded evidence. `ProgressTracker` receives the quality history plus those relevant-path digests; unrelated changes do not reset a repeated-fingerprint stall. A stable normalized-action digest is UTF-8 canonical JSON with sorted object keys, no insignificant whitespace, and SHA-256; the digest covers kind, validated arguments, and rationale.

Approval records retain the normalized action, digest, repository snapshot digest, decision, and execution state. `pending_approval(task_id)` is a formal `AgentLoop` query. A decision is single-use; duplicate or terminal decisions raise `ApprovalStateError`. Resume reacquires the repository lease, compares the saved snapshot to the current snapshot, and blocks with drift feedback if it differs. Revalidation receives the action and current snapshot; it may allow, deny, or require a new approval. Approved dispatch uses a durable intent record before the filesystem effect and a completion record after it; recovery observes the intent and the expected after-digest, never blindly replays an already-applied patch. This is idempotent at-least-once recovery, not an impossible cross-resource transaction.

`TaskRepository` provides compare-and-set state transitions, transition intents, approval lookup/decision/execution marking, lease acquire/release, and recovery snapshots. Leases release on every terminal transition and on a waiting approval after the snapshot is saved. `AgentLoop` receives repository, policy, dispatcher, pipeline, parser, LLM, context builder, progress tracker, clock, and an audit sink through explicit constructor protocols. The injected audit sink redacts metadata from Task 8 onward; Task 9 supplies the JSONL implementation. Transition records contain digests and bounded redacted summaries, never complete prompts or model responses. Storage, verifier/tool availability, configuration, and permission failures are `BLOCKED`; unrecoverable internal consistency failures are `FAILED`.


## 15. Design Decisions Summary

- Focus on a deep structured quality-feedback pipeline rather than general extensibility.
- Support Python only, using pytest and Ruff.
- Use local repository path plus natural-language task as the input.
- Keep a narrow validator interface without dynamic plugin loading.
- Use typed tools and no arbitrary shell.
- Persist structured state in SQLite and retrieve context with deterministic rules.
- Use an operating-system credential store for real provider keys.
- Deliver a local real-mode WebUI and a public mock-only demonstration.
