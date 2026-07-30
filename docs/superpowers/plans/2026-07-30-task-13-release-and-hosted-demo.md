# Task 13 Release and Hosted Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish PyQuality Harness to a new public GitHub repository, obtain real green CI evidence, deploy the credential-free public mock service on Render, verify the hosted demonstration, and record truthful final evidence.

**Architecture:** A local release gate first closes Task 12 evidence and proves the exact publish commit. GitHub publication and Render deployment are separate externally reviewed tasks with idempotent discovery before creation. A final evidence task records observed URLs/results, pushes that documentation commit, and re-verifies CI and hosted behavior on the resulting remote state.

**Tech Stack:** Git, GitHub Actions, GitHub web UI or authenticated repository tooling, Render Docker Web Service, in-app browser automation, Python 3.12+, pytest, Ruff, hatchling/PEP 517.

## Global Constraints

- Implement `docs/superpowers/specs/2026-07-30-task-13-release-and-hosted-demo-design.md` exactly.
- Begin repository changes in a Superpowers-owned isolated worktree from the resolved plan commit; external publication uses the reviewed commits from that branch and never force-pushes.
- The user explicitly authorized a public GitHub repository named `pyquality-harness` and public source publication.
- Create at most one public GitHub repository and one free Render Web Service; discover existing resources before every create operation.
- Never create a paid resource, supply billing information, publish to PyPI, push a registry image, configure a custom domain, or expose provider mode.
- Never extract, print, persist, or commit passwords, cookies, access tokens, CSRF values, Render keys, provider credentials, local databases, audit logs, or ignored development residue.
- Pause for user interaction on login, MFA, CAPTCHA, account recovery, ambiguous organization, repository-name collision, broader-than-needed OAuth consent, or any billing request.
- Use browser automation through the installed browser-control skill for interactive external UI; do not use broad web search as an authenticated-control substitute.
- Do not claim remote CI, deployment, hosted acceptance, screenshots, or URLs unless directly observed.
- Repository changes use strict RED-to-GREEN. External failures are reproduced locally with a failing test when technically reproducible; never weaken tests/security to obtain green status.
- Task 11/11A breaker history and Task 11B remediation remain intact. Task 12 closes only with its actual final CLEAN result and Docker-local capability limitation.

---

### Task 1: Close Local Release Evidence and Freeze the Publish Gate

**Files:**
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `tests/distribution/test_artifacts.py`

**Interfaces:**
- Consumes: merged Task 12 final commit `e7892cd`, final scoped CLEAN review, current distribution contract, and Task 13 public-release approval.
- Produces: truthful Task 12 completion evidence, Task 13 pre-publication status, and an executable local publish gate.

- [ ] **Step 1: Add local release-evidence RED tests**

Extend the independent root-evidence validator with exact current semantics:

```python
EXPECTED_TASK_12_STATUS = "Complete"
EXPECTED_TASK_12_FINAL_COMMIT = "e7892cd"
EXPECTED_TASK_13_STATUS = "In progress"
```

Require PLAN/AGENT_LOG to state that Task 12 final review was CLEAN, local Docker remained unavailable, no local image build was claimed, and Task 13 public publication was explicitly approved but no remote URL/CI/deploy result existed at that point. Add mutation cases rejecting a fabricated repository URL, green CI claim, hosted URL, or Docker success.

- [ ] **Step 2: Run evidence tests and capture RED**

```powershell
$env:PYTHONPATH='src'
D:\Python\python.exe -m pytest tests/distribution/test_artifacts.py -k "task12_completion or task13_prepublication" -v --basetemp "$env:TEMP\pyquality-task13-red-local-evidence"
```

Expected: fail because Task 12 remains recorded with broad review pending and Task 13 has no ledger/evidence entry.

- [ ] **Step 3: Synchronize only observed local evidence**

Update PLAN/AGENT_LOG with Task 12 final CLEAN and `e7892cd`; add Task 13 as in progress/pre-publication with human authorization, repository/CI/deployment fields explicitly pending. Do not add example URLs that could be mistaken for evidence.

- [ ] **Step 4: Rerun unchanged tests to GREEN and run local release gate**

Run the Step 2 selector unchanged, then:

```powershell
$env:PYTHONPATH='src'
D:\Python\python.exe -m pytest -q --basetemp "$env:TEMP\pyquality-task13-local-full"
D:\Python\python.exe -m ruff check src tests
D:\Python\python.exe -m build --no-isolation --outdir "$env:TEMP\pyquality-task13-dist"
git grep -n -E 'sk-[A-Za-z0-9]{12,}|Bearer [A-Za-z0-9._-]{12,}' -- ':!tests/**' ':!docs/**'
git diff --check
```

Inspect wheel/sdist for required runtime assets and prohibited tests/examples/Git/SDD/database/audit/cache content. Install the wheel into a temporary system-site-packages venv outside the checkout and run CLI help plus deterministic demo.

- [ ] **Step 5: Commit and review Task 1**

```powershell
git add PLAN.md AGENT_LOG.md tests/distribution/test_artifacts.py
git commit -m "docs: close Task 12 release gate"
```

Record exact tests, archive hashes, approval, and Docker-local limitation in the ignored SDD report. Generate a frozen review package and obtain spec/quality approval before external creation.

---

### Task 2: Create the Public GitHub Repository and Obtain Green CI

**Files:**
- Modify: `README.md`
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `tests/distribution/test_artifacts.py`
- Modify: the narrowest CI/application/test file only if a real remote CI failure proves it necessary

**Interfaces:**
- Consumes: Task 1 reviewed publish commit and the existing `.github/workflows/ci.yml`.
- Produces: public GitHub repository `pyquality-harness`, configured local `origin`, remote `master`, a real successful Actions run, and evidence-backed repository/CI documentation.

- [ ] **Step 1: Open GitHub and verify account state**

Use the browser-control skill to open GitHub. If login/MFA/CAPTCHA is shown, pause for the user. Once authenticated, record only the visible account login in the ignored task report; never inspect cookies/tokens.

- [ ] **Step 2: Discover before creating**

Search the signed-in account for an exact repository named `pyquality-harness`. If one exists, stop for user direction; do not overwrite, delete, rename, transfer, or reuse it automatically.

- [ ] **Step 3: Create the repository exactly once**

Create a public repository named `pyquality-harness` with no generated README, license, or `.gitignore`. Capture the visible repository HTTPS URL. Confirm its default branch state is empty before configuring local Git.

- [ ] **Step 4: Configure origin and push without force**

```powershell
git remote -v
$githubCloneUrl = 'the exact HTTPS clone URL visibly returned by GitHub in Step 3'
git remote add origin $githubCloneUrl
git push -u origin HEAD:master
```

If browser/credential-manager authentication is required, pause for the user. Verify `git ls-remote origin refs/heads/master` equals the reviewed feature-branch HEAD. This publishes the isolated Task 13 branch as remote `master` without prematurely merging local `master`. Never push other branches or tags in this step.

- [ ] **Step 5: Observe the initial Actions run**

Open the Actions run for the pushed commit. Wait with bounded refreshes until terminal. Require every required step—pytest, Ruff, package, Docker build—to succeed. Record run URL, commit SHA, job names, conclusion, and timestamps in the ignored report.

If a job fails, capture bounded sanitized logs. Reproduce locally, add a literal failing test, make the narrowest fix, obtain task re-review, push normally, and wait for the replacement run. A remote-only infrastructure outage remains blocked rather than converted to success.

- [ ] **Step 6: Add repository/CI evidence tests and capture RED**

Add tests requiring README/PLAN/AGENT_LOG to contain the exact observed repository URL and Actions run URL, commit SHA, and successful conclusion while still marking Render deployment pending. The expected values are explicit test constants copied from observed evidence, not parsed from the documents themselves. Run and record RED before document edits.

- [ ] **Step 7: Record evidence, commit, push, and verify the evidence commit**

Update README/PLAN/AGENT_LOG with exact GitHub and CI evidence. Commit:

```powershell
git add README.md PLAN.md AGENT_LOG.md tests/distribution/test_artifacts.py
git commit -m "docs: record public repository and CI evidence"
git push origin master
```

Wait for Actions on this documentation commit and require it to pass. Verify remote master equals local HEAD. Generate the task report/review package and obtain spec/quality approval before Render creation.

---

### Task 3: Deploy and Verify the Render Public Mock Service

**Files:**
- Modify: `README.md`
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `tests/distribution/test_artifacts.py`
- Modify: the narrowest container/application/test file only if a real deployment failure proves it necessary

**Interfaces:**
- Consumes: reviewed GitHub repository/green CI commit and the repository Dockerfile.
- Produces: one free Render Docker Web Service, public HTTPS URL, deployment record, and hosted deterministic `SUCCEEDED` evidence.

- [ ] **Step 1: Open Render and verify authentication/plan**

Use browser control. Pause for login, MFA, CAPTCHA, OAuth scope expansion, organization ambiguity, or billing. Proceed only when a free Web Service is visibly available.

- [ ] **Step 2: Discover before creating**

Search the selected Render workspace for an existing service tied to the repository or named `pyquality-harness`. If found, stop for user direction; do not replace or reconfigure it automatically.

- [ ] **Step 3: Create the service**

Authorize repository read/deploy access only as needed. Select repository `pyquality-harness`, branch `master`, Docker runtime, free plan, and health path `/`. Add `PYQUALITY_MODE=public_mock` only if the UI requires an explicit value; add no secrets, provider key, database URL, or persistent disk.

- [ ] **Step 4: Observe deployment to terminal state**

Wait with bounded refreshes. Require Render to identify the expected Git commit and report a successful deploy. Record public HTTPS URL, deployed SHA, deploy URL/identifier, and visible timestamps without copying secret configuration.

- [ ] **Step 5: Perform hosted browser acceptance**

Open the public URL. Create the bundled demo task through the UI, follow its task page with bounded navigation, and require terminal `SUCCEEDED`. Verify visible deterministic guardrail/feedback/progress evidence and absence of credential prompts, provider configuration, local paths, prompt/source bodies, and server errors.

- [ ] **Step 6: Add hosted-evidence tests and capture RED**

Add explicit expected constants for the observed Render URL, deployed SHA, and terminal result. Require README/PLAN/AGENT_LOG to document the actual service, mock-only and free-tier limitations, and successful hosted acceptance. Run RED before document edits.

- [ ] **Step 7: Record, commit, push, and re-deploy evidence commit**

```powershell
git add README.md PLAN.md AGENT_LOG.md tests/distribution/test_artifacts.py
git commit -m "docs: record hosted mock demonstration evidence"
git push origin master
```

Require GitHub Actions to pass for this commit. If Render auto-deploy is enabled, require that commit to deploy and repeat hosted acceptance; otherwise trigger one normal deploy from `master` and repeat. Record the final remote results in the ignored task report without creating another tracked self-referential evidence update.

- [ ] **Step 8: Review Task 3**

Generate a frozen package containing tracked documentation/tests and sanitized external evidence references. Reviewer verifies URLs and visible states independently where accessible; authentication-only Render dashboard details remain report evidence, while the public service is directly verifiable.

---

### Task 4: Final Release Audit and Evidence Handoff

**Files:**
- Modify: `PLAN.md`
- Modify: `AGENT_LOG.md`
- Modify: `README.md`
- Modify: `tests/distribution/test_artifacts.py`
- Modify: `SPEC.md` or `SPEC_PROCESS.md` only if a direct audit proves an approved required fact is absent

**Interfaces:**
- Consumes: all reviewed task commits, final GitHub Actions URL/result, final Render URL/deployed commit, and hosted `SUCCEEDED` acceptance.
- Produces: final locally verified course records and a frozen broad-review package; the external report records post-commit CI/deployment verification to avoid false self-reference.

- [ ] **Step 1: Audit every task row and process record**

Use Git history and retained evidence to ensure completed Tasks 0–12 have real commits and two-stage review outcomes. Confirm `SPEC_PROCESS.md` already includes the Task 0 agent type, supplied inputs, questions, divergent interpretations, and resulting changes; do not invent additions.

- [ ] **Step 2: Add final record-mutation tests and capture RED**

Require exact repository/CI/Render URLs, mock-only status, hosted `SUCCEEDED`, Task 13 reviewed task commits, and truthful limitations. Mutation cases must reject fabricated URLs, failed/pending CI relabeled green, provider-mode deployment, paid-resource claims, and missing historical breakers.

- [ ] **Step 3: Make the narrowest evidence corrections**

Update only facts proven by prior tasks. Mark Task 13 implementation tasks clean and broad final review pending; do not claim the broad review before it occurs. Keep final post-commit remote verification in the ignored report.

- [ ] **Step 4: Run final local and remote verification**

Run full pytest, Ruff, build/inspection, isolated wheel CLI/demo, secret scan, and diff check. Push the final evidence commit normally, require GitHub Actions green, require Render to deploy the same commit, and repeat hosted `SUCCEEDED` acceptance.

- [ ] **Step 5: Commit and prepare broad review**

```powershell
git add README.md PLAN.md AGENT_LOG.md tests/distribution/test_artifacts.py
git add SPEC.md SPEC_PROCESS.md  # only when Step 1 proved a required gap
git commit -m "docs: record final release verification evidence"
git push origin master
```

Record the resulting commit, CI run URL, deploy SHA, public acceptance, and exact verification output in ignored evidence. Generate the cumulative package from the Task 13 execution base and dispatch the broad final reviewer. No tracked file may claim that review before its verdict exists.
