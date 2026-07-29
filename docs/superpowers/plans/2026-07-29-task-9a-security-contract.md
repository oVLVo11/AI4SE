# Task 9A Security Contract Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two human-approved Task 9 breaker findings by making credential-result normalization closed under configured byte limits and making Windows audit-file privacy atomic at creation and fail-closed for existing files.

**Architecture:** Credential callback results cross a strict 4 KiB textual boundary before any value can be returned; numeric equivalence is evaluated only inside a canonical domain whose alternative accepted representations also fit that boundary. Windows audit files are created with an owner-only protected DACL supplied directly to `NtCreateFile`; existing files are opened without sharing, verified owner-only through the retained handle, and rejected rather than retroactively hardened when permissive.

**Tech Stack:** Python 3.12, Pydantic 2, `decimal.Decimal`, Windows `ntdll`/`advapi32`/`kernel32` through `ctypes`, pytest, Ruff.

## Global Constraints

- Provider callback text results exceeding 4,096 UTF-8 bytes are rejected before return, irrespective of whether they contain a registered secret.
- Credential strings remain bounded by the existing credential input contract. Numeric-looking credential strings outside the canonical domain are rejected at `set`, rather than stored as ordinary text.
- The canonical numeric domain must be closed under every accepted textual spelling within 4,096 UTF-8 bytes. Equivalent accepted integer, fixed-decimal, and exponent spellings produce one identity; nonnumeric API keys remain exact text.
- Numeric provider objects outside the safe bit/digit/exponent domain fail closed before expensive conversion. Arbitrary objects are never inspected through `repr`.
- On Windows, a newly created audit file receives the protected owner-only DACL atomically through the `OBJECT_ATTRIBUTES.SecurityDescriptor` supplied to `NtCreateFile`. There is no inherited-permission exposure window.
- On Windows, an existing audit file is opened with no sharing, so incompatible pre-existing handles cause a typed sanitized failure. Its retained handle must already identify the current process-token owner and an exact protected owner-only DACL; otherwise emission fails without modifying the DACL.
- Audit-file traversal remains retained-handle, component-relative, and reparse-safe. Descriptor locking, tail recovery, complete writes, `fsync`, handle cleanup, URL preservation, recursive redaction bounds, and POSIX behavior remain unchanged.
- Tests are deterministic and offline. Windows-native assertions run on Windows; portable contract tests verify structure/arguments where another platform cannot execute the APIs. Skips name only a precise unavailable platform capability.
- Core code imports no FastAPI. Root course documents are updated only after the remediation passes technical review.

---

### Task 1: Close Credential and Windows Audit Atomicity Contracts

**Files:**
- Modify: `src/pyquality/security.py`
- Modify: `tests/security/test_credentials.py`
- Modify: `tests/security/test_redaction.py`
- Create: `tests/component/test_audit_process.py`

**Interfaces:**
- Consumes: `CredentialService.set/get`, `AuditLogger.emit`, the current descriptor-locking and Windows retained-handle helpers.
- Produces: unchanged public method signatures with stricter typed failures at the approved boundaries.

- [ ] **Step 1: Write failing credential-domain tests**

Add literal table cases proving that a stored credential `1e4096` is rejected at `set`; provider text of 4,097 UTF-8 bytes is rejected before return; the largest accepted exponent/fixed/integer equivalences whose spellings fit 4,096 bytes share an identity; ordinary values such as `sk-live-1e4096` remain exact text; and huge numeric objects fail closed without `str`/Decimal expansion.

- [ ] **Step 2: Run the credential tests and verify RED**

Run: `python -m pytest tests/security/test_credentials.py -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-9a-security-contract/pytest-credential-red`

Expected: FAIL because `1e4096` is accepted as a credential and the 4,097-byte equivalent provider result can be returned.

- [ ] **Step 3: Implement the closed 4 KiB credential domain**

Reject provider string/bytes results above 4,096 UTF-8 bytes before recursive echo inspection. Parse numeric-looking credential input at `set`; reject numeric forms whose canonical equivalence class is not closed inside the accepted 4 KiB textual boundary. Reuse one Decimal tuple identity for accepted stored and returned forms, and preserve exact matching for nonnumeric text.

- [ ] **Step 4: Run credential tests and verify GREEN**

Run the Step 2 command again.

Expected: PASS with pristine output.

- [ ] **Step 5: Write failing atomic Windows DACL tests**

On Windows, intercept/inspect the final `NtCreateFile` call and assert a non-null protected owner-only security descriptor is present when the file is newly created. Create an existing permissive audit file and prove emission fails without changing its DACL. Hold an incompatible external handle and prove exclusive open fails with sanitized `AuditWriteError`. Verify a valid pre-secured existing file emits successfully and all native handles/descriptors are released.

- [ ] **Step 6: Run the Windows audit tests and verify RED**

Run: `python -m pytest tests/security/test_redaction.py tests/component/test_audit_process.py -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-9a-security-contract/pytest-audit-red`

Expected: FAIL because final creation supplies `SecurityDescriptor=None` and existing files are hardened after shared open.

- [ ] **Step 7: Implement atomic creation and fail-closed existing-file opening**

Build the current-user owner-only protected security descriptor before final creation and pass it in `OBJECT_ATTRIBUTES`. Distinguish create-new from open-existing without a path race using retained-handle/native disposition results. For existing files, request no sharing, verify owner/DACL via the handle, and never call the DACL mutation path. Keep all security descriptor, SID, token, native, and CRT ownership transfers exception-safe.

- [ ] **Step 8: Run audit tests and verify GREEN**

Run the Step 6 command again.

Expected: PASS with only precise platform-capability skips.

- [ ] **Step 9: Run complete verification**

Run: `python -m pytest tests/security tests/component/test_audit_process.py -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-9a-security-contract/pytest-focused`

Run: `python -m pytest -v -p no:cacheprovider --basetemp .superpowers/sdd/2026-07-29-task-9a-security-contract/pytest-full`

Run: `ruff check src tests`

Run: `git diff --check`

Expected: all tests pass with only precise platform skips; Ruff and diff check are clean.

- [ ] **Step 10: Commit**

```bash
git add src/pyquality/security.py tests/security/test_credentials.py tests/security/test_redaction.py tests/component/test_audit_process.py
git commit -m "fix: close credential and audit creation contracts"
```
