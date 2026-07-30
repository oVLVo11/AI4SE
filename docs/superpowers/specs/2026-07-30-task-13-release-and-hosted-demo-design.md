# Task 13 Release and Hosted Demo Design

**Status:** Approved design; written specification pending user review

## Purpose

Task 13 publishes the reviewed PyQuality Harness course project to a public GitHub repository, obtains real remote CI evidence, deploys the credential-free public mock service on Render, and records only observed release evidence.

The user has explicitly authorized publishing the current project source in a public repository. Task 13 creates no paid resource and never publishes provider credentials, local databases, audit logs, cookies, access tokens, or ignored development residue.

## Release Topology

The release uses two external surfaces:

1. A public GitHub repository named `pyquality-harness` with local `master` pushed as its default branch.
2. A Render Docker Web Service built from that GitHub repository and running the existing mock-only container command.

GitHub Actions is the authoritative remote test, lint, package, and Docker-build evidence. Render is the authoritative hosted demonstration evidence. Local results remain supporting evidence and are not substituted for either remote result.

Alternative hosts or repository names require a new explicit user decision. GitHub Pages is not a substitute because the project requires a Python web service.

## GitHub Publication and CI

Create the repository under the user's currently authenticated GitHub account. Before creation, verify the signed-in account and that no repository with the selected name would be overwritten. The repository is public and has no auto-generated README, license, or `.gitignore` that could conflict with local history.

Add the new repository as the local `origin` only after confirming its exact clone URL. Push `master` without force. Do not rewrite remote history, push ignored files, or publish other local branches.

The existing GitHub Actions workflow must run on the pushed commit and visibly complete:

- pytest;
- Ruff;
- wheel/sdist build and distribution checks;
- Docker image build.

Record the actual workflow URL, commit SHA, conclusion, and relevant job names. A queued, skipped, cancelled, neutral, or partially successful run is not recorded as passing. If CI exposes a product or delivery defect, reproduce it locally when possible, add a failing regression test, implement the minimum reviewed correction, and push a normal follow-up commit. Do not weaken tests, security boundaries, or workflow requirements to obtain green status.

## Render Deployment

Create one Render Web Service from the public GitHub repository using its Dockerfile. Use a free plan when available; if Render requires payment, a credit card, or a paid resource, stop and request user direction.

The service configuration is:

- Docker runtime from the repository Dockerfile;
- default branch `master`;
- public HTTP service;
- `PYQUALITY_MODE=public_mock` only when Render requires an explicit environment setting in addition to the image;
- no provider API key, authorization header, keyring material, database URL, secret file, or persistent disk;
- health verification through `/`;
- automatic deploys may be enabled only for `master` after the first successful deployment.

Do not add dummy values that resemble real secrets. Do not switch to local/provider mode to make deployment work.

## Hosted Acceptance

After Render reports a successful deploy, verify the actual public HTTPS URL in a browser:

1. Open `/` and confirm the public mock landing/task interface loads without authentication or server error.
2. Create the bundled demonstration task through the public interface.
3. Follow the returned task page until it reaches a terminal state using bounded polling or normal UI navigation.
4. Confirm the terminal status is `SUCCEEDED` and the rendered evidence shows the deterministic guardrail/feedback/progress behavior required by the course mechanism demo.
5. Confirm the public surface does not request or display a provider key and exposes no local path, prompt/source body, credential, database content, or audit token.

Record the public URL, observation time, deployed Git commit, terminal result, and limitations. Do not record session cookies, CSRF values, internal Render deployment tokens, full response bodies containing user input, or browser authentication state.

## Documentation and Evidence Closure

Update `README.md` with the actual repository URL, GitHub Actions run URL, public Render URL, deployment instructions, mock-only limitation, free-tier cold-start limitation when observed, and the tested commit SHA.

Update `PLAN.md` and `AGENT_LOG.md` using actual evidence:

- close Task 12 as complete only after its already returned final CLEAN review, naming the final commit and Docker-local capability limitation;
- record Task 13 implementation identity, human approval to publish publicly, repository creation, push result, CI URL/conclusion, deployment URL/result, hosted acceptance, review verdicts, and final verification;
- preserve Task 11 and Task 11A breaker history and Task 11B remediation history;
- do not invent missing identities, remote pipeline URLs, deployment screenshots, or success results.

`SPEC_PROCESS.md` is modified only if its required pre-implementation evidence is demonstrably incomplete. `SPEC.md` is modified only if the release exposes an already approved normative requirement that is absent. Neither file becomes a chronological deployment log.

## Authentication and External-Action Boundaries

Use an existing authenticated browser session or user-configured credential flow. Never extract, print, copy, or persist browser cookies, personal access tokens, Render API keys, or passwords into the repository, terminal output, task reports, or model context.

Pause for the user when:

- GitHub or Render requires login, MFA, CAPTCHA, organization approval, or account recovery;
- repository creation would collide with an existing repository;
- Render requests billing information or a paid plan;
- an OAuth authorization requests permissions broader than repository read/deploy access needed for this task;
- external account ownership or target organization is ambiguous.

The user may complete an interactive authentication step in the browser; automation resumes only after the page visibly confirms success.

## Verification and Failure Semantics

Before external publication, run the complete local suite, Ruff, package build/inspection, secret scan, and `git diff --check` on the exact commit to be pushed.

After publication, verify:

- `origin` points to the newly created repository;
- remote `master` resolves to the intended local commit;
- GitHub Actions has a real successful run for that commit;
- Render deploys that commit and reports success;
- hosted acceptance reaches `SUCCEEDED`;
- final local verification remains green after evidence-document updates.

Any unavailable external service, authentication requirement, remote failure, or deployment failure is recorded as a blocker with its sanitized visible error and URL when safe. It is not reclassified as a passing capability skip. Network retries are bounded and do not create duplicate repositories or services.

## Scope and Review

Task 13 may modify `README.md`, `PLAN.md`, `AGENT_LOG.md`, focused distribution/evidence tests, and the narrowest CI/container/application fix proven necessary by a real remote failure. It may modify `SPEC.md` or `SPEC_PROCESS.md` only under the evidence rules above.

It may create one public GitHub repository and one free Render Web Service. It must not create paid resources, publish packages to PyPI, push a container registry image, configure a custom domain, expose provider mode, or delete/replace existing remote resources.

Task 13 uses strict RED-to-GREEN for repository changes and a five-round review budget. Each implementation task receives specification-compliance and code-quality review, followed by a broad final review. The project is complete only when local release verification, remote CI, hosted acceptance, and final review are all clean.
