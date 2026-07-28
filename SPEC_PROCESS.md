# PyQuality Harness Specification Process Record

## Evidence and Provenance

This record distinguishes controller-supplied conversation facts from repository evidence. The raw conversation transcript is not stored in this repository. The controller supplied the facts below on 2026-07-28 for this record; no quotes or conversation timestamps are reconstructed.

Repository evidence:

- Approved design: `docs/superpowers/specs/2026-07-28-pyquality-harness-design.md`, committed as `de51d59` on 2026-07-28.
- Reviewed implementation plan: `docs/superpowers/plans/2026-07-28-pyquality-harness.md`, committed as `743b69c` on 2026-07-28.

## Brainstorming Alternatives

| Alternative | Disposition | Recorded rationale |
| --- | --- | --- |
| Structured feedback pipeline | Adopted (recommended selection) | Keeps the primary contribution deep: parse failures, classify them, select minimal evidence, construct next context, and detect stalls or repetition. |
| Plugin-style validators | Rejected | Extensibility work would dilute the intended feedback-loop depth. |
| Event-driven workflow | Rejected | Too heavy for the local-first harness scope. |

## Key Dialogue Iterations

1. The controller recorded that the user selected quality-loop scenario C, then chose Python-only option A, a local repository path plus natural-language task option A, and pytest plus Ruff option A.
2. The user selected the deep-feedback option A: parse, classify, choose minimal evidence, build the next context, and detect stall/repeat conditions. The user then directed that later choices use the recommended option.
3. To reconcile local repository paths with a required public WebUI, the proposed design adopted local-first real mode and a hosted mock-only demonstration. The user stated no extra platform or provider constraints.
4. A Visual Companion was offered just in time for architecture and explicitly declined.
5. Seven design sections were individually approved, followed by overall approval and approval of the written specification. Their original spoken headings are not preserved; the traceability map below maps those approvals to the approved design without inventing labels.

## Seven Approved Design Sections: Traceability Map

| Approval section | Approved-design coverage |
| --- | --- |
| 1. Problem, scope, goals, and user stories | Sections 1–3 |
| 2. Task lifecycle, typed tools, and quality feedback | Sections 4.1–4.3 |
| 3. Progress, stopping, governance, memory, and configuration | Sections 4.4–4.8 |
| 4. Coding-domain mechanisms and architecture | Sections 5–6 |
| 5. Data model and durable state | Section 7 |
| 6. Security, credentials, technology, distribution, and deployment | Sections 8–9 |
| 7. Error handling, observability, testing, and demonstration | Sections 10–11 |

## Adopted and Rejected Suggestions

Adopted: structured feedback as the primary contribution; Python-only scope; a local repository and natural-language task input; pytest and Ruff verification; local-first real mode with a hosted mock-only public demonstration; recommendation-led later choices.

Rejected: validator-plugin extensibility, an event-driven workflow, and the Visual Companion.

## Cold-start Validation

Completed on 2026-07-28. The exact validator output is preserved in `docs/superpowers/reviews/2026-07-28-cold-start-validation.md`; this section indexes that evidence and records the resulting corrections.

### Validator Identity and Scope

- Agent: `/root/task0_docs_coldstart/coldstart_validator`
- Model: `gpt-5.6-sol`
- Context supplied: only `SPEC.md` and `PLAN.md` paths plus the instruction to dry-run Task 1 and one risk-heavy task, write no implementation code, and stop at uncertainty.
- Chosen risk-heavy task: Task 8.
- Result: completed without implementation edits.

### Actual Task 1 Findings

Questions: exact fields/invariants for `QualityReport`, `TaskResult`, `PolicyOutcome`, `ToolResult`, `ApprovalDecision`, and `AuditEvent`; enum versus structured `PolicyOutcome`; typed union versus dictionary action arguments; public-model unknown-field policy; repository-relative versus absolute `Finding.path`; limits for strings and arguments; whether line may lack a path; full-quality success fields; iteration counting; configuration tables/keys; coexistence and precedence of `pyproject.toml` and `pyquality.toml`; user-file format/optionality; secure default values and safe pytest/Ruff arguments; whether repository configuration may reduce security limits; parse/type/conflict error behavior; invalid or symlinked repository-root behavior; Python 3.12-only interpretation; and editable-install implications.

Divergent interpretations: typed action envelope versus per-tool payloads; scope of unknown-field rejection; ordinary override merge versus monotonic security merge; repository configuration files as equivalent, complementary, or conflicting; and display finding categories versus stable serialized values.

Expected mismatches: the Task 1 console entry point precedes `cli.py`; dictionary action arguments conflict with the no-untyped-public-boundary goal; Task 3 names `PolicyDecision` while consuming `PolicyOutcome`; Tasks 5, 6, and 8 require undefined quality/result/iteration semantics; Task 2 lacks typed persistence inputs for architecture entities; and broad dependency ranges do not make installation reproducible.

### Actual Task 8 Findings

Questions: complete states/transitions; iteration and round accounting; repair-attempt and provider-retry accounting; verification triggers for patch, `run_quality`, and `finish`; patch/path/content-digest supply; relevant-versus-unrelated change handling; approval revalidation, canonicalization, digest, repository drift, lease, deadline, duplicate-decision, and terminal-resume semantics; rejection feedback and LLM exhaustion; blocked-versus-failed classification; redacted pre-Task-9 audit persistence; and crash semantics for a filesystem effect plus SQLite state.

Divergent interpretations: persistence as intent/outbox versus simple pre-effect state save; impossible cross-resource transaction versus chosen recovery guarantee; response-versus-action meaning of model round; lease retention versus release while awaiting approval; terminal-decision timing; whether denials/approvals occupy iterations; and whether Task 8 directly interprets quality results or delegates to `ProgressTracker`.

Expected mismatches: no aggregate core-protocol constructor boundary; missing repository APIs for approval/recovery transitions; one-action iteration storage versus repair persistence; revalidation missing action/snapshot inputs; `ToolResult` lacks changed-file data; `ProgressTracker` lacks relevant-change input; parser/LLM retry ownership is not defined; audit/redaction arrives after Task 8; `pending_approval()` exists only in examples; and fixture signatures do not establish a construction contract.

### Corrections Made

Specification section 14 and the matching root `SPEC.md` now define the requested model/configuration contract, state-transition and round accounting, typed tool-result data, deterministic digest, approval/lease/drift/recovery rules, repository and dependency-injection interfaces, and pre-Task-9 redacted audit sink. The canonical plan and root `PLAN.md` add matching Task 1–8 consumption and production amendments. These corrections directly address the findings above; no product code was written.
