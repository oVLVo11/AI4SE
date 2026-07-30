# Public Mock Execution Design

## Context

The deployed public mock accepts the bundled `broken_calculator` scenario, but `PublicDemoService.run_scenario()` currently stores only a static `CREATED` task. Repeated reads therefore remain at `CREATED` with eight rounds remaining. Task 13 requires the hosted service to execute the bundled offline harness and expose truthful, sanitized terminal evidence.

## Scope and Success Criteria

The public form submission must execute the existing deterministic offline demo without repository input, provider credentials, external model access, a database, a worker, or persistent storage. A successful submission redirects to `/tasks/public-demo`, which reports `SUCCEEDED`, zero remaining rounds, and a bounded public summary of policy, feedback, progress, and action-order evidence.

The implementation remains a free-tier, single-process demonstration. Results are process-local and may disappear on restart. A user can rerun the bundled scenario to recreate the result.

## Architecture and Data Flow

`PublicDemoService` receives a callable demo runner. Production composition injects a wrapper around the existing `run_demo()` and supplies a temporary working directory for each invocation. Tests inject a deterministic runner directly.

`run_scenario()` performs these steps synchronously:

1. Validate that the scenario identifier maps to the fixed public task ID.
2. Execute the injected offline runner once.
3. Convert its report into a purpose-built public result containing only approved booleans, counts, enums, and fixed action labels.
4. Atomically replace the process-local result for `public-demo`.
5. Return a task view with terminal `SUCCEEDED` status and zero remaining rounds.

The Web route continues redirecting to `/tasks/public-demo`. The task template receives the task view and its bounded public result. No background execution or polling state is introduced.

## Public Evidence Model

The public result exposes only the evidence necessary for the hosted demonstration:

- terminal status `SUCCEEDED`;
- zero remaining rounds;
- confirmation that an outside-repository action was denied and not dispatched;
- the fixed first failure category;
- confirmation that feedback reached the model;
- bounded progress/action-order labels needed to show correction and completion.

It must not expose repository paths, temporary paths, source bodies, patch bodies, prompts, raw model responses, credentials, provider configuration, timestamps, audit payloads, or the complete internal `DemoReport`.

## Failure Handling

Unknown scenarios remain rejected. If the runner raises, the service must not retain a partial success result. The Web boundary returns a stable retryable failure response containing only `public demo execution failed`; exception text, exception type details, paths, source, and prompts remain private.

Repeated successful runs replace the previous in-memory result rather than accumulating sessions or user data. The capability restriction remains structural: public composition has no repository service, credential service, external provider, database, or arbitrary request input.

## Testing

Implementation follows test-driven development:

1. Add a failing service/Web test that requires the runner to execute once and the redirected task page to report `SUCCEEDED` with zero rounds.
2. Add a failing sanitization test for a runner exception containing a sensitive local path and verify only the stable public message is returned.
3. Add failing assertions for the approved guardrail, feedback, progress, and action-order summary while rejecting source, patch, prompt, path, credential, and provider leakage.
4. Add repeated-run and capability-boundary coverage.
5. Implement the narrowest service, composition, view, and template changes needed to pass.

Before publication, run focused tests, the complete pytest suite, Ruff, isolated wheel/sdist construction, secret scanning, and diff checks. Obtain task review before pushing. After push, require GitHub Actions to pass, Render to deploy the same commit, and a fresh hosted form submission to reach `SUCCEEDED` with the approved sanitized evidence.

## Non-Goals

This change does not add asynchronous workers, a durable database, multi-user history, provider mode, arbitrary repositories or prompts, credentials, persistent disks, paid Render resources, or a general-purpose hosted coding agent.
