# Task 12 Course Delivery Design

**Status:** Approved design; written specification pending user review

## Purpose

Task 12 turns the reviewed PyQuality Harness implementation into locally verifiable course deliverables. It supplies the required documentation, distribution metadata, continuous-integration definitions, and mock-only container contract without claiming external deployment evidence that does not yet exist.

Task 11, Task 11A, and Task 11B evidence is synchronized into the root course records as part of this work. Task 13 remains locked until Task 12 passes independent review.

## Contract-First Structure

`tests/distribution/test_artifacts.py` is the executable boundary for delivery artifacts. Tests are written and observed failing before creating or changing delivery files. They validate file presence, required README sections, CI commands, Docker public-mode restrictions, package data, and exclusions.

The delivery surfaces share one runtime contract:

- editable development installs and built wheels expose the same `pyquality` CLI;
- the wheel contains templates and bundled deterministic demo resources required at runtime;
- CI builds and tests the same package metadata used locally;
- the container installs the built wheel rather than running from an editable source tree;
- the container starts only `pyquality serve --host 0.0.0.0 --port 8000 --public-mock` with `PYQUALITY_MODE=public_mock` and no provider credential.

The only application-surface amendment permitted by Task 12 is the missing composition-layer selector required to make the already approved public-mock deployment runnable. The `serve` command accepts `--public-mock`; either that flag or `PYQUALITY_MODE=public_mock` selects the existing public-mock service composition. This does not change the agent loop, provider client, policy, persistence, audit formats, or local-mode semantics.

## Course Documentation

Create `README.md` with these exact second-level sections:

- `Installation`
- `Running`
- `Distribution`
- `Credential Security`
- `Project Structure`
- `Safety Boundaries`
- `Known Limitations`

The README documents supported Python versions, editable and wheel installation, CLI and deterministic demo commands, local WebUI operation, public mock isolation, keyring storage, the warned environment-variable fallback, pytest code-execution risk, build commands, container operation, and a Render-compatible container deployment procedure. It must not claim a hosted URL, successful remote pipeline, published package, or pushed image.

Update `PLAN.md` and `AGENT_LOG.md` with evidence that can be traced to existing commits, test output, and independent reviews. Preserve the historical Task 11 and Task 11A breaker records, then record Task 11B as the approved remediation that closed the remaining POSIX receipt-directory durability defect. Do not rewrite a blocked task as though it had never failed.

Update `SPEC.md` or `SPEC_PROCESS.md` only when required to synchronize already approved design/process facts. Do not invent missing cold-start dialogue, agent identities, commit hashes, review verdicts, CI results, or deployment evidence.

## CI Contracts

Create `.github/workflows/ci.yml` for pushes and pull requests. It has explicit jobs or clearly separated steps for:

- `pytest -q`;
- `ruff check src tests`;
- `python -m build` followed by distribution inspection or installation testing;
- `docker build .`.

Use a supported Python version allowed by `pyproject.toml`. Dependency installation uses the project metadata and development extra rather than a second hand-maintained dependency list.

Create `.gitlab-ci.yml` containing the course-required job:

```yaml
unit-test:
  image: python:3.12-slim
  script:
    - python -m pip install -e ".[dev]"
    - pytest -q
```

Additional safe setup is allowed only when needed for deterministic execution; the required job name and commands remain recognizable and executable.

## Distribution and Container

Update `pyproject.toml` only as required for PEP 517 wheel/sdist creation, the `build` development dependency, package discovery, and runtime package data. The built artifacts include Web templates and deterministic demo resources but exclude tests, local databases, credentials, audit logs, SDD scratch, caches, and repository-only examples unless explicitly needed at runtime.

Create `Dockerfile` and `.dockerignore`. The Docker build uses a builder stage to create a wheel and a smaller runtime stage to install it. The runtime image:

- copies only bundled runtime examples/resources;
- defines no real API key or credential placeholder that could be mistaken for one;
- sets `PYQUALITY_MODE=public_mock`;
- exposes port 8000;
- starts the public mock command directly;
- does not mount or copy host databases, audit roots, Git metadata, test output, or SDD artifacts.

The image contract is mock-only. Local/provider mode remains a host-side operation with the existing credential boundary.

## Verification and Failure Semantics

Verification is evidence-driven:

1. Run the distribution contract tests and record genuine RED.
2. Implement the minimum artifact set and rerun the same tests to GREEN.
3. Build one wheel and one sdist with `python -m build`.
4. Inspect archive contents and install the wheel into an isolated environment; verify CLI import/help and the deterministic mock demo without source-tree imports.
5. Run `docker build -t pyquality-harness:local .` and inspect its configured command/environment when Docker is available.
6. Run the secret-pattern scan, complete pytest suite, Ruff, and `git diff --check`.

The distribution contract includes an executable CLI test, not only Dockerfile text inspection. It must prove that `pyquality serve --host 0.0.0.0 --port 8000 --public-mock` parses successfully and constructs the existing public-mock application without reading a provider credential or making a network request. A second test proves `PYQUALITY_MODE=public_mock` selects the same composition when the flag is absent. Invalid environment values fail typed at startup rather than silently selecting local or public mode.

A missing or inaccessible Docker daemon is recorded as an environment capability blocker for the image-build evidence. It must not be reported as a successful build, replaced with fabricated output, or worked around by weakening the Docker contract tests. Non-Docker distribution work may still be reviewed, but Task 12 cannot be declared fully verified until the approved review process adjudicates that capability result.

Errors and documentation must not disclose credentials, authorization headers, full prompts, model bodies, owner tokens, absolute audit paths, or secret-bearing exception chains.

## Scope and Review

Task 12 may modify only:

- `SPEC.md`, `PLAN.md`, `SPEC_PROCESS.md`, and `AGENT_LOG.md` for evidence-backed synchronization;
- `README.md`;
- `.github/workflows/ci.yml` and `.gitlab-ci.yml`;
- `Dockerfile` and `.dockerignore`;
- `pyproject.toml`;
- focused distribution tests and small packaging fixtures required by those tests.
- `src/pyquality/cli.py` and focused CLI/service tests solely for the approved `--public-mock` and `PYQUALITY_MODE=public_mock` composition selector.

It must not change agent-loop behavior, provider semantics, security policy, audit formats, other public APIs, demo semantics, Task 11B durability logic, user-provided untracked course source documents, or Task 13 hosted evidence.

Task 12 receives a five-round task-review budget. Each implementation task requires specification-compliance and code-quality approval, followed by a broad final review.
