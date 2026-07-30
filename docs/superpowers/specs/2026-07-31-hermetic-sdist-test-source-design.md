# Hermetic sdist Test Source Design

## Context

The sdist exclusion regression currently copies the entire repository before seeding `.venv-sentinel`. In the main Windows workspace, unrelated inaccessible `.pytest-task*` residue makes `shutil.copytree()` fail before the test reaches the packaging contract. The identical tracked commit passes in the isolated Task 13 worktree and in GitHub Actions, proving the failure comes from untracked workspace state rather than the distribution implementation.

## Goal

Make the sdist regression independent of Git and arbitrary workspace residue while preserving its mutation-catching proof that root virtual-environment variants are excluded from source distributions.

## Design

Add a test-only `_copy_sdist_source(source_root: Path) -> None` helper in `tests/distribution/test_artifacts.py`. The helper copies only explicit build inputs required by the Hatch sdist build:

- `pyproject.toml`;
- `README.md` and any root license file required by package metadata;
- the complete tracked `src/` tree, including templates and demo fixtures.

The helper does not enumerate or copy the repository root wholesale. It does not use Git, inspect untracked paths, follow other worktrees, or touch user documents, pytest residue, virtual environments, build outputs, or local databases.

After copying the build inputs, the test deliberately creates `.venv-sentinel/marker` inside the isolated source tree. It builds the sdist there and asserts that no archive path component starts with `.venv` and that the marker is absent. Required runtime inputs, templates, and demo fixtures must remain present.

## Error and Scope Boundaries

Missing required build inputs fail the test immediately with the normal filesystem error; the helper does not silently skip them. No production source, packaging metadata, ignore file, workspace permissions, or existing residue is changed. The change is limited to the distribution test helper and its regression coverage.

## Testing

Follow RED → GREEN:

1. Reproduce the current main-workspace failure caused by inaccessible `.pytest-task*` residue.
2. Add a focused test or direct helper assertion proving only the explicit build inputs are copied and an unrelated inaccessible/untracked directory is never traversed.
3. Replace the whole-repository copy with `_copy_sdist_source()` and require the sdist exclusion test to pass in the main workspace.
4. Temporarily remove the `/.venv*` exclusion in the isolated copied configuration and require the archive regression to fail; restore it and require GREEN.
5. Run the distribution suite, full pytest suite, Ruff, and `git diff --check` on the final merged result.

## Non-Goals

This change does not delete or repair ACLs on existing residue, broaden `.gitignore` or `.dockerignore`, change production packaging contents, or introduce a Git dependency into distribution tests.
