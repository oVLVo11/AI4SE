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

Pending. This section will contain only the fresh agent's actual questions, divergent interpretations, expected file/interface mismatches, and the narrow corrections made in response. The validator is instructed to stop at uncertainty rather than guess.

