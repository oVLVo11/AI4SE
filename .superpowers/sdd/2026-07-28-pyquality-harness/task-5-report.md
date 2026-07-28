# Task 5 Report: Pytest/Ruff Validators and Finding Parsers

## Scope delivered

- Added `parsers.py` with deterministic, UTF-8-bounded pytest and Ruff JSON parsing.
- Added explicit finding categories for syntax, import/collection, assertion, runtime,
  timeout, missing tool dependency, and unmatched infrastructure failures.
- Added `validators.py` with `RawValidationResult`, interpreter-module invocation,
  targeted-test preflight, full pytest, Ruff JSON, status mapping, command capture,
  elapsed duration, and SHA-256 output digest capture.
- Added POSIX and Windows-path fixtures plus parser and component-runner coverage.

## TDD evidence

1. `python -m pytest tests/unit/test_parsers.py -v` initially failed at collection
   because `pyquality.parsers` did not exist.
2. Parser implementation was added; the focused parser suite then passed (9 tests).
3. `python -m pytest tests/component/test_validators.py -v` initially failed at
   collection because `pyquality.validators` did not exist.
4. Validator implementation was added; focused parser/component tests passed (13 tests).

## Fresh verification

Executed after the completion-verification check:

```text
python -m pytest -v
126 passed, 5 skipped in 3.07s

python -m ruff check src tests
All checks passed!

git diff --check
exit 0
```

## Review fix round 1

- Honored validated `pytest_args` and `ruff_args`, replacing any configured Ruff
  output-format pair with exactly one JSON protocol pair.
- Limited targeted-preflight short-circuiting to timeouts, absent exit status, and
  explicit missing-tool failures, so pytest exit 5 still permits the mandatory suite.
- Sanitized invalid pytest line bounds and boolean/non-positive Ruff rows.
- Passed effective Settings limits through both parser paths and Finding validation.
- Excluded Windows drive-qualified changed paths from repository targets.
- Added Ruff group/code as a deterministic ordering tie-breaker.

TDD evidence for this round:

1. The first focused run collected 22 tests and failed 10 tests for the six reviewed
   behaviors before production changes.
2. After the minimal fixes, all 22 focused tests passed.
3. A pipeline-level pytest Settings-limit test was then added and failed with 124
   evidence bytes against a 16-byte limit before Settings was threaded through that path.
4. The final focused run passed 23 tests.

Fresh verification after review fixes:

```text
python -m pytest tests/unit/test_parsers.py tests/component/test_validators.py -v
23 passed in 0.14s

python -m pytest -v
136 passed, 5 skipped in 3.41s

python -m ruff check src tests
All checks passed!

git diff --check
exit 0
```

## Contract note

`QualityReport` was consumed without schema changes. The required raw command
duration and output digest are carried on `RawValidationResult`; normalized report
status, findings, commands, timeout labels, and changed paths remain in the
existing `QualityReport` contract.
