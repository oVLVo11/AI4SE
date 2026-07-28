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

## Contract note

`QualityReport` was consumed without schema changes. The required raw command
duration and output digest are carried on `RawValidationResult`; normalized report
status, findings, commands, timeout labels, and changed paths remain in the
existing `QualityReport` contract.
