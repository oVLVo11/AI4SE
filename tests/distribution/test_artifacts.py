"""Distribution artifacts remain safe, runnable, and self-contained."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TASK_12_STATUS = "Complete"
EXPECTED_TASK_12_FINAL_COMMIT = "e7892cd"
EXPECTED_TASK_12_SPEC_REVIEW = (
    "`/root/task12_task1_review`: final scoped review CLEAN; "
    "broad final review CLEAN"
)
EXPECTED_TASK_12_QUALITY_REVIEW = (
    "Final controller/merged verification at e7892cd: full pytest to 100%; "
    "Ruff and diff exit 0; Docker CLI unavailable; no local image build claimed"
)
EXPECTED_TASK_12_COMMITS = (
    "6d06a3e",
    "783a814",
    "869dd20",
    "8e1792d",
    "2313c29",
    "5ebe41b",
    "469d268",
    "1d37067",
    "f916136",
    EXPECTED_TASK_12_FINAL_COMMIT,
)
EXPECTED_TASK_13_STATUS = (
    "In progress; implementation tasks reviewed; final broad review pending"
)
EXPECTED_TASK_13_AGENT = "`/root/task13_github`, `/root/task13_render`"
EXPECTED_TASK_13_SPEC_REVIEW = (
    "Task 1, Task 2, public-mock subplan, and Task 3 scoped reviews CLEAN; "
    "final broad review pending"
)
EXPECTED_TASK_13_QUALITY_REVIEW = (
    "Verified pre-audit head 82958a8: GitHub Actions 30567593776 success with "
    "pytest, Ruff, package, and Docker; hosted public mock reached SUCCEEDED; "
    "final broad review pending"
)
EXPECTED_TASK_13_COMMITS = (
    "7f8dd42",
    "1d4c237",
    "9fdd7c4",
    "89544fc",
    "cc7ea93",
    "a1672c4",
    "ad4229c",
    "c49283f",
    "aceb2d7",
    "710600d",
    "3d90e63",
    "9127380",
    "f776f1e",
    "690e23e",
    "06a5bf8",
    "82958a8",
)
EXPECTED_EARLY_TASK_ROWS = {
    "0": (
        "Complete",
        "`/root/task0_docs_coldstart`, `/root/task0_docs_coldstart/coldstart_validator`",
        "Clean re-review",
        "Documentation contract checks clean",
        "`2fdb099`, `b5cdd29`, `efc73b3`",
    ),
    "1": (
        "Complete",
        "`/root/task1_domain_config`",
        "Clean after fix round 3",
        "47 passed; Ruff clean",
        "`297d277`, `6df8353`, `a3908f9`, `920983e`, `a200b8b`",
    ),
    "2": (
        "Complete",
        "`/root/task2_storage_memory`",
        "Clean after fix round 1",
        (
            "64 passed; Ruff clean; two deferred minors: repository close/context-manager "
            "support and directory-prefix/validator-scope selector tests"
        ),
        "`73261de`, `a606267`",
    ),
}
EXPECTED_TASK_3_TO_10_ROWS = {
    "3": ("Complete", "`/root/task3_policy`", "Human ruling: SPEC §14.2 is binding for revalidation; clean after fix round 1", "88 passed; 3 WinError-1314 symlink skips; Ruff clean; deferred Minor: threshold-boundary coverage", "`7b570c2`, `422382f`"),
    "4": ("Complete", "`/root/task4_tools`, `/root/task4_fix_round4`", "Clean after fix round 4", "113 passed; 5 skipped; Ruff clean; portable POSIX syscall contract passed locally, while the POSIX rename/symlink end-to-end test was unavailable on the Windows host", "`b7a5d6c`, `ae7785d`, `c20a668`, `14becd2`, `6eea0e9`"),
    "5": ("Complete", "Initial implementer identity unavailable after context compaction; `/root/task5_fix1` (fix rounds)", "`/root/task5_review`: clean after fix round 2", "140 passed; 5 skipped; Ruff and diff-check clean", "`411f7ae`, `ba45a82`, `f5e8145`"),
    "6": ("Complete", "`/root/task6_feedback`", "`/root/task5_review`: clean after fix round 3", "Primary implementation verification: 164 passed; 5 skipped; focused 24 passed; Ruff and diff-check clean. Final reviewer full runs encountered unrelated pre-existing Task 4 one-second timeout flakes that passed in isolation; no Task 6 regression found", "`7a55808`, `c45d2da`, `4831d09`, `b8b54d6`"),
    "7": ("Complete", "`/root/task7_llm_context`", "`/root/task7_review`: clean after fix round 1", "177 passed; 5 skipped; focused 13 passed; Ruff and diff-check clean; deferred Minor: explicit primitive-root, undeclared-extra-field, and lowered contextual-limit parser tests", "`9941c80`, `08b93a6`"),
    "8": ("Complete", "`/root/task8_agent_loop`, `/root/task8_fix4`", "`/root/task8_review`: clean after fix round 4", "Pristine full suite: 264 passed; 6 skipped; focused 98 passed, 1 WinError-1314 alias skip; exact round-4 regression 3 passed; Ruff and diff-check clean; deferred Minor: constructor dependencies are not all protocols", "`80d54ec`, `7712349`, `adc6777`, `c3b5c0a`, `3a50249`, `4c9ea1a`"),
    "9": ("Complete", "Initial implementer identity unavailable; `/root/task9a_remediation` (Task 9A)", "Task 9A clean after fix round 1; prior five-round breaker resolved by approved contract amendment", "Focused 90 passed, 2 skipped; full 354 passed, 8 skipped; Ruff and diff-check clean", "`66631d3`, `d6349b5`, `bc2b1c2`, `4f2fd8c`, `25a80e9`, `b593a49`, `6a2c885`, `4e4899b`, `964e818`, `9ab2f10`"),
    "10": ("Complete", "Initial implementer and remediation identities unavailable after context compaction", "Independent Task 10A review clean after fix round 2; prior five-round breaker resolved by approved lifecycle amendment", "Affected 157 passed; pristine full 460 passed, 8 skipped; Ruff and cumulative diff-check clean", "`49072fe`, `65f26c2`, `88993f7`, `9fb90d0`, `67f4e39`, `3b3859f`, `f0c5fa4`, `71efb7c`, `0a4a15c`, `eb7afd3`, `6e4b44e`"),
}
EXPECTED_TASK_0_SUBSTANTIVE_FACTS = (
    "exact fields/invariants for `QualityReport`, `TaskResult`, `PolicyOutcome`, `ToolResult`, `ApprovalDecision`, and `AuditEvent`",
    "typed action envelope versus per-tool payloads",
    "the Task 1 console entry point precedes `cli.py`",
    "approval revalidation, canonicalization, digest, repository drift, lease, deadline, duplicate-decision, and terminal-resume semantics",
    "persistence as intent/outbox versus simple pre-effect state save",
    "no aggregate core-protocol constructor boundary",
    "requested model/configuration contract",
    "state-transition and round accounting",
    "pre-Task-9 redacted audit sink",
    "canonical plan and root `PLAN.md` add matching Task 1",
)
EXPECTED_PUBLIC_REPOSITORY_URL = "https://github.com/oVLVo11/AI4SE.git"
EXPECTED_INITIAL_CI_URL = "https://github.com/oVLVo11/AI4SE/actions/runs/30544072702"
EXPECTED_INITIAL_CI_SHA = "89544fc9d295fdbe0d6d20fd1ffc202d5238144f"
EXPECTED_INITIAL_CI_CONCLUSION = "success"
EXPECTED_HOSTED_URL = "https://ai4se.onrender.com"
EXPECTED_HOSTED_SHA = "82958a82dfc12b171691042c012c5279ae639dea"
EXPECTED_RENDER_DEPLOY_ID = "dep-d9loso4s728c739i80rg"
EXPECTED_HOSTED_TERMINAL_RESULT = "SUCCEEDED"
EXPECTED_FINAL_CI_URL = "https://github.com/oVLVo11/AI4SE/actions/runs/30567593776"
EXPECTED_FINAL_CI_JOB_URL = f"{EXPECTED_FINAL_CI_URL}/job/90955887900"
EXPECTED_FINAL_CI_CONCLUSION = "success"
EXPECTED_FINAL_CI_RECORD = (
    f"Final GitHub Actions run {EXPECTED_FINAL_CI_URL} completed with conclusion "
    f"`{EXPECTED_FINAL_CI_CONCLUSION}` for `{EXPECTED_HOSTED_SHA}`; job "
    f"{EXPECTED_FINAL_CI_JOB_URL} reported pytest, Ruff, package, and Docker successful."
)
EXPECTED_HOSTED_LIMITATION = (
    "No credentials, provider configuration, database, or persistent disk are "
    "attached to this free-tier public mock service."
)
EXPECTED_DASHBOARD_PROVENANCE = (
    "The Render deploy SHA and deploy ID are user-supplied dashboard evidence."
)
EXPECTED_ACCEPTANCE_PROVENANCE = (
    "Hosted acceptance was independently verified by the controller through the "
    "real HTTP CSRF form."
)
EXPECTED_CI_PROVENANCE = (
    "The controller independently verified GitHub CI through the GitHub API."
)
EXPECTED_PROCESS_LOCAL_LIMITATION = (
    "Task results are process-local and may return HTTP 404 after a restart or "
    "free-tier sleep until the bundled scenario is rerun."
)
EXPECTED_ACCEPTANCE_TIME = "2026-07-30 17:50:41 GMT"
EXPECTED_ACCEPTANCE_RECORD = (
    f"At `{EXPECTED_ACCEPTANCE_TIME}`, the controller independently repeated the real "
    f"hosted CSRF flow and received HTTP 200 at {EXPECTED_HOSTED_URL}/tasks/public-demo "
    "with terminal `SUCCEEDED` and zero remaining rounds."
)
EXPECTED_NO_LEAKAGE_RECORD = (
    "The public response contained no forbidden local or temporary paths, `LEAK` "
    "sentinels, prompt/source/patch bodies, provider key, credential prompt, traceback, "
    "or server error."
)
EXPECTED_DOCKER_LIMITATION = (
    "Local Docker CLI remains unavailable; no local Docker success is claimed."
)
EXPECTED_REVIEW_STATUS = (
    "Task 13 implementation tasks are reviewed; final broad review pending."
)
EXPECTED_NO_SELF_REFERENCE = (
    f"These tracked records cover verified pre-audit commit `{EXPECTED_HOSTED_SHA}` and "
    "do not claim CI or deployment success for the later final-audit commit; post-commit "
    "remote verification belongs only in ignored evidence."
)
EXPECTED_GUARDRAIL_EVIDENCE = "Guardrail: `outside action denied`."
EXPECTED_FEEDBACK_EVIDENCE = "Feedback: `assertion`."
EXPECTED_PROGRESS_EVIDENCE = (
    "Progress: `read_file -> apply_patch -> apply_patch -> finish`."
)


def _read(relative_path: str) -> str:
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


def _copy_sdist_source(source_root: Path) -> None:
    source_root.mkdir()
    pyproject = REPOSITORY_ROOT / "pyproject.toml"
    shutil.copy2(pyproject, source_root / "pyproject.toml")
    shutil.copy2(REPOSITORY_ROOT / "README.md", source_root / "README.md")

    license_specification = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"].get(
        "license"
    )
    if isinstance(license_specification, dict) and "file" in license_specification:
        license_filename = license_specification["file"]
        if not isinstance(license_filename, str):
            raise TypeError("project license file must be a string")
        shutil.copy2(
            REPOSITORY_ROOT / license_filename,
            source_root / license_filename,
        )

    shutil.copytree(REPOSITORY_ROOT / "src", source_root / "src")


def _task_ledger_rows(plan: str) -> dict[str, tuple[str, str, str, str, str]]:
    header = "| Task | Status | Implementing agent | Spec review | Quality review | Commit |"
    table = plan[plan.index(header) :]
    rows: dict[str, tuple[str, str, str, str, str]] = {}
    for line in table.splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) == 6:
            rows[cells[0]] = tuple(cells[1:])  # type: ignore[assignment]
    return rows


def _bounded_section(document: str, start: str, end: str | None = None) -> str:
    assert document.count(start) == 1
    section = document[document.index(start) :]
    if end is not None:
        assert end in section
        section = section[: section.index(end)]
    return section


def _validate_current_task13_sections(readme: str, plan: str, agent_log: str) -> None:
    sections = (
        _bounded_section(readme, "### Render-compatible deployment"),
        _bounded_section(plan, "### Task 13: Final Release and Hosted Demonstration Evidence", "**Files:**"),
        _bounded_section(agent_log, "## 2026-07-31 Task 13 hosted public mock evidence"),
    )
    required = (
        EXPECTED_PUBLIC_REPOSITORY_URL,
        EXPECTED_INITIAL_CI_URL,
        EXPECTED_INITIAL_CI_SHA,
        EXPECTED_HOSTED_URL,
        EXPECTED_HOSTED_SHA,
        EXPECTED_RENDER_DEPLOY_ID,
        EXPECTED_HOSTED_TERMINAL_RESULT,
        EXPECTED_FINAL_CI_RECORD,
        EXPECTED_HOSTED_LIMITATION,
        EXPECTED_DASHBOARD_PROVENANCE,
        EXPECTED_ACCEPTANCE_PROVENANCE,
        EXPECTED_CI_PROVENANCE,
        EXPECTED_PROCESS_LOCAL_LIMITATION,
        EXPECTED_ACCEPTANCE_RECORD,
        EXPECTED_NO_LEAKAGE_RECORD,
        EXPECTED_DOCKER_LIMITATION,
        EXPECTED_REVIEW_STATUS,
        EXPECTED_NO_SELF_REFERENCE,
        EXPECTED_GUARDRAIL_EVIDENCE,
        EXPECTED_FEEDBACK_EVIDENCE,
        EXPECTED_PROGRESS_EVIDENCE,
    )
    forbidden = (
        "has production availability",
        "live provider mode",
        "paid service",
        "durable task storage",
        "Task 3 review CLEAN",
        "Task 3 review complete",
        "Task 13 final broad review complete",
        "final broad review CLEAN",
        "CI and Render deployed commit `06a5bf8`",
        "the final-audit commit passed CI",
        "the final-audit commit deployed",
        "this final audit commit passed CI",
        "this final audit commit deployed",
        "authenticated browser",
        "Hosted acceptance was user-supplied",
        "30562643715",
        "690e23e2544936c0bde3e507730c63d34da6af0f",
        "dep-d9lntmcs728c739h5ffg",
        "https://github.com/example/",
        "https://example.onrender.com",
        "dep-example",
        "`FAILED`",
    )
    allowed_urls = {
        EXPECTED_PUBLIC_REPOSITORY_URL,
        EXPECTED_INITIAL_CI_URL,
        EXPECTED_FINAL_CI_URL,
        EXPECTED_FINAL_CI_JOB_URL,
        "https://github.com/oVLVo11/AI4SE/actions/runs/30561047811",
        EXPECTED_HOSTED_URL,
        f"{EXPECTED_HOSTED_URL}/tasks",
        f"{EXPECTED_HOSTED_URL}/tasks/public-demo",
    }
    allowed_full_shas = {EXPECTED_INITIAL_CI_SHA, EXPECTED_HOSTED_SHA}

    for section in sections:
        for text in required:
            assert text in section
        for text in forbidden:
            assert text.casefold() not in section.casefold()
        for label in ("Guardrail:", "Feedback:", "Progress:"):
            assert len(re.findall(rf"(?m)^{label} .+$", section)) == 1
        urls = {
            match.rstrip(".,;")
            for match in re.findall(r"https://[^\s`)]+", section)
        }
        assert urls <= allowed_urls
        assert set(re.findall(r"\b[0-9a-f]{40}\b", section)) <= allowed_full_shas
        assert set(re.findall(r"\bdep-[a-z0-9]+\b", section)) <= {
            EXPECTED_RENDER_DEPLOY_ID
        }


def _validate_root_evidence(plan: str, agent_log: str) -> None:
    ledger = _task_ledger_rows(plan)
    for task in ("0", "1", "2", "11", "11A", "11B", "12", "13"):
        assert task in ledger
        status, agent, spec_review, quality_review, commits = ledger[task]
        assert all((status, agent, spec_review, quality_review, commits))
        assert agent == "unavailable" or re.fullmatch(r"`/root/[^`]+`(?:, `/root/[^`]+`)*", agent)
        assert re.search(r"\b[0-9a-f]{7,40}\b", commits)

    for task, expected in EXPECTED_EARLY_TASK_ROWS.items():
        assert ledger[task] == expected
    for task, expected in EXPECTED_TASK_3_TO_10_ROWS.items():
        assert ledger[task] == expected

    assert ledger["11"][0] == "Implemented; breaker reached"
    assert ledger["11A"][0] == "Blocked; breaker reached"
    assert ledger["11B"][0] == "Complete"
    assert "CLEAN" in ledger["11B"][2]
    assert ledger["12"][0].strip() == EXPECTED_TASK_12_STATUS
    assert ledger["12"][2].strip() == EXPECTED_TASK_12_SPEC_REVIEW
    assert ledger["12"][3].strip() == EXPECTED_TASK_12_QUALITY_REVIEW
    assert ledger["13"][0].strip() == EXPECTED_TASK_13_STATUS
    assert ledger["13"][1].strip() == EXPECTED_TASK_13_AGENT
    assert ledger["13"][2].strip() == EXPECTED_TASK_13_SPEC_REVIEW
    assert ledger["13"][3].strip() == EXPECTED_TASK_13_QUALITY_REVIEW
    assert "breaker" in ledger["11"][2].lower()
    assert "breaker" in ledger["11"][3].lower()
    assert "clean" not in ledger["11"][2].lower()
    assert "clean" not in ledger["11"][3].lower()
    assert "fifth review" in ledger["11A"][2].lower()
    assert "breaker" in ledger["11A"][3].lower()
    assert "clean" not in ledger["11A"][2].lower()
    assert "clean" not in ledger["11A"][3].lower()
    assert "CLEAN" in ledger["11B"][2]
    assert "CLEAN" in ledger["11B"][3]

    required_commits = {
        "0": ("2fdb099", "b5cdd29", "efc73b3"),
        "1": ("297d277", "6df8353", "a3908f9", "920983e", "a200b8b"),
        "2": ("73261de", "a606267"),
        **{
            task: tuple(re.findall(r"\b[0-9a-f]{7,40}\b", row[4]))
            for task, row in EXPECTED_TASK_3_TO_10_ROWS.items()
        },
        "11": (
            "593384e", "e80a17d", "6dcc2ec", "16b4edc", "ba8d95b", "d60a8bc", "10339c0",
            "7c21ce6", "39a21c4", "5ad427a", "f363ccc", "90b9c45", "9f44513",
        ),
        "11A": ("87e5ad7", "63b08cf", "07cffcd", "5eb42fb", "ea569a9", "47bed5d", "6de2411"),
        "11B": ("d396c24", "e7448ff", "cad8e17"),
        "12": EXPECTED_TASK_12_COMMITS,
        "13": EXPECTED_TASK_13_COMMITS,
    }
    for task, expected in required_commits.items():
        actual = tuple(re.findall(r"\b[0-9a-f]{7,40}\b", ledger[task][4]))
        assert actual == expected

    headings = (
        "## 2026-07-29 Task 11 implementation and breaker",
        "## 2026-07-30 Task 11A remediation and breaker",
        "## 2026-07-30 Task 11B remediation and CLEAN review",
        "## 2026-07-30 Task 12 distribution work",
        "## 2026-07-30 Task 12 Task 2 review CLEAN and broad final re-review pending",
        "## 2026-07-30 Task 12 final unified fix and CLEAN closure",
        "## 2026-07-30 Task 13 pre-publication gate",
    )
    heading_positions = [agent_log.index(heading) for heading in headings]
    assert heading_positions == sorted(heading_positions)

    early_headings = (
        "## 2026-07-28 Task 3 revalidation ruling",
        "## 2026-07-28 Task 3 implementation and fix round 1",
        "## 2026-07-28 Task 4 clarified tool restrictions",
        "## 2026-07-28 Task 4 implementation and review fixes",
        "## 2026-07-28 Task 5 implementation and review fixes",
        "## 2026-07-29 Task 6 implementation and review fixes",
        "## 2026-07-29 Task 7 implementation and review fix",
        "## 2026-07-29 Task 8 implementation and review fixes",
        "## 2026-07-29 Task 9 implementation, breaker, and Task 9A remediation",
        "## 2026-07-29 Task 10 implementation, breaker, and Task 10A remediation",
    )
    early_positions = [agent_log.index(heading) for heading in early_headings]
    assert early_positions == sorted(early_positions)
    assert early_positions[-1] < heading_positions[0]
    early_required = (
        ("SPEC §14.2", "422382f", "clean"),
        ("b7a5d6c", "6eea0e9", "fix round 4"),
        ("411f7ae", "f5e8145", "clean"),
        ("7a55808", "b8b54d6", "clean"),
        ("9941c80", "08b93a6", "clean"),
        ("80d54ec", "4c9ea1a", "clean"),
        ("five formal fix rounds", "Task 9 breaker", "964e818", "9ab2f10"),
        ("Five formal fix rounds", "breaker stopped Task 11", "0a4a15c", "6e4b44e"),
    )
    boundaries = ((0, 2), (2, 4), (4, 5), (5, 6), (6, 7), (7, 8), (8, 9), (9, None))
    sections = [
        agent_log[early_positions[start] : (early_positions[end] if end is not None else heading_positions[0])]
        for start, end in boundaries
    ]
    for section, required in zip(sections, early_required, strict=True):
        for text in required:
            assert text.casefold() in section.casefold()

    task_11 = agent_log[heading_positions[0] : heading_positions[1]].lower()
    task_11a = agent_log[heading_positions[1] : heading_positions[2]].lower()
    task_11b = agent_log[heading_positions[2] : heading_positions[3]]
    task_12_review = agent_log[heading_positions[4] : heading_positions[5]]
    task_12_final = agent_log[heading_positions[5] : heading_positions[6]]
    task_13 = agent_log[heading_positions[6] :]
    assert "breaker" in task_11
    assert "breaker" in task_11a
    assert "remaining" in task_11b.lower() and "defect" in task_11b.lower()
    assert "CLEAN" in task_11b
    assert "Task 2 review CLEAN" in task_12_review
    assert "broad final re-review remains pending" in task_12_review
    assert "Task 12 is not complete" in task_12_review
    assert "Docker CLI remains unavailable" in task_12_review
    for text in (
        EXPECTED_TASK_12_FINAL_COMMIT,
        "final scoped review CLEAN",
        "broad final review CLEAN",
        "full pytest to 100%",
        "Ruff and diff exit 0",
        "Docker CLI remains unavailable",
        "no local image build claimed",
    ):
        assert text in task_12_final
    for text in (
        EXPECTED_PUBLIC_REPOSITORY_URL,
        EXPECTED_INITIAL_CI_URL,
        EXPECTED_INITIAL_CI_SHA,
        EXPECTED_INITIAL_CI_CONCLUSION,
        EXPECTED_HOSTED_URL,
        EXPECTED_HOSTED_SHA,
        EXPECTED_RENDER_DEPLOY_ID,
        EXPECTED_HOSTED_TERMINAL_RESULT,
        EXPECTED_FINAL_CI_URL,
        EXPECTED_FINAL_CI_CONCLUSION,
        EXPECTED_HOSTED_LIMITATION,
        EXPECTED_REVIEW_STATUS,
    ):
        assert text in task_13
    for commit in ("6de2411", "cad8e17", *EXPECTED_TASK_12_COMMITS):
        assert commit in agent_log


def _validate_task0_process_record(spec_process: str) -> None:
    for text in (
        "- Agent: `/root/task0_docs_coldstart/coldstart_validator`",
        "- Model: `gpt-5.6-sol`",
        (
            "- Context supplied: only `SPEC.md` and `PLAN.md` paths plus the instruction "
            "to dry-run Task 1 and one risk-heavy task, write no implementation code, and "
            "stop at uncertainty."
        ),
        "### Actual Task 1 Findings",
        "### Actual Task 8 Findings",
        "Questions:",
        "Divergent interpretations:",
        "Expected mismatches:",
        "### Corrections Made",
        "These corrections directly address the findings above; no product code was written.",
    ):
        assert text in spec_process
    for text in EXPECTED_TASK_0_SUBSTANTIVE_FACTS:
        assert text in spec_process


def test_task12_completion_records_final_clean_local_evidence() -> None:
    _validate_root_evidence(_read("PLAN.md"), _read("AGENT_LOG.md"))


def test_task13_final_release_audit_records_exact_evidence() -> None:
    ledger = _task_ledger_rows(_read("PLAN.md"))
    assert ledger["12"][0].strip() == EXPECTED_TASK_12_STATUS
    assert ledger["12"][2].strip() == EXPECTED_TASK_12_SPEC_REVIEW
    assert ledger["12"][3].strip() == EXPECTED_TASK_12_QUALITY_REVIEW
    assert tuple(re.findall(r"\b[0-9a-f]{7,40}\b", ledger["12"][4])) == EXPECTED_TASK_12_COMMITS
    assert ledger["13"] == (
        EXPECTED_TASK_13_STATUS,
        EXPECTED_TASK_13_AGENT,
        EXPECTED_TASK_13_SPEC_REVIEW,
        EXPECTED_TASK_13_QUALITY_REVIEW,
        ", ".join(f"`{commit}`" for commit in EXPECTED_TASK_13_COMMITS),
    )
    _validate_root_evidence(_read("PLAN.md"), _read("AGENT_LOG.md"))
    _validate_current_task13_sections(
        _read("README.md"), _read("PLAN.md"), _read("AGENT_LOG.md")
    )
    _validate_task0_process_record(_read("SPEC_PROCESS.md"))
    for document in ("README.md", "PLAN.md", "AGENT_LOG.md"):
        content = _read(document)
        for expected in (
            EXPECTED_PUBLIC_REPOSITORY_URL,
            EXPECTED_INITIAL_CI_URL,
            EXPECTED_INITIAL_CI_SHA,
            EXPECTED_INITIAL_CI_CONCLUSION,
            EXPECTED_HOSTED_URL,
            EXPECTED_HOSTED_SHA,
            EXPECTED_RENDER_DEPLOY_ID,
            EXPECTED_HOSTED_TERMINAL_RESULT,
            EXPECTED_FINAL_CI_URL,
            EXPECTED_FINAL_CI_CONCLUSION,
            EXPECTED_FINAL_CI_RECORD,
            EXPECTED_HOSTED_LIMITATION,
            EXPECTED_DASHBOARD_PROVENANCE,
            EXPECTED_ACCEPTANCE_PROVENANCE,
            EXPECTED_CI_PROVENANCE,
            EXPECTED_PROCESS_LOCAL_LIMITATION,
            EXPECTED_ACCEPTANCE_RECORD,
            EXPECTED_NO_LEAKAGE_RECORD,
            EXPECTED_DOCKER_LIMITATION,
            EXPECTED_REVIEW_STATUS,
            EXPECTED_NO_SELF_REFERENCE,
        ):
            assert expected in content


@pytest.mark.parametrize(
    ("path", "old", "new"),
    (
        ("PLAN.md", "Clean re-review", "Review pending"),
        ("PLAN.md", "Clean after fix round 3", "Review pending"),
        ("PLAN.md", "Clean after fix round 1", "Review pending"),
        ("PLAN.md", "Implemented; breaker reached", "Complete; CLEAN"),
        ("PLAN.md", "Blocked; breaker reached", "Complete; CLEAN"),
        (
            "PLAN.md",
            EXPECTED_TASK_12_STATUS,
            "In progress; evidence pending",
        ),
        (
            "PLAN.md",
            (
                "`6d06a3e`, `783a814`, `869dd20`, `8e1792d`, `2313c29`, `5ebe41b`, "
                "`469d268`, `1d37067`, `f916136`, `e7892cd`"
            ),
            "`deadbee`",
        ),
        ("AGENT_LOG.md", "`783a814`", "`amendment unavailable`"),
    ),
)
def test_root_evidence_contract_rejects_reviewed_history_mutations(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    old: str,
    new: str,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    documents[path] = documents[path].replace(old, new)

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task12_completion_records_final_clean_local_evidence()


@pytest.mark.parametrize(
    ("path", "replacements"),
    (
        (
            "PLAN.md",
            (
                (
                    (
                "`6d06a3e`, `783a814`, `869dd20`, `8e1792d`, `2313c29`, "
                "`5ebe41b`, `469d268`, `1d37067`, `f916136`, `e7892cd`"
                    ),
                    (
                "`6d06a3e`, `783a814`, `869dd20`, `8e1792d`, `2313c29`, "
                "`5ebe41b`, `469d268`, `1d37067`, `f916136`, `e7892cd`, `deadbee`"
                    ),
                ),
            ),
        ),
        (
            "PLAN.md",
            (("Five-round review breaker", "CLEAN"), ("517 passed, 9 skipped; five-round breaker", "CLEAN")),
        ),
        (
            "PLAN.md",
            (("Task and final review CLEAN; focused durability 11 passed; affected 128 passed, 4 skipped; full 581 passed, 10 skipped; Ruff and diff clean", "FAILED"),),
        ),
    ),
)
def test_root_evidence_contract_rejects_false_commits_and_review_verdicts(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    replacements: tuple[tuple[str, str], ...],
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    for old, new in replacements:
        documents[path] = documents[path].replace(old, new)

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task12_completion_records_final_clean_local_evidence()


def test_root_evidence_contract_rejects_task12_docker_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    documents["PLAN.md"] = documents["PLAN.md"].replace(
        EXPECTED_TASK_12_QUALITY_REVIEW,
        "Task 12 complete; Docker image build succeeded",
    )

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task12_completion_records_final_clean_local_evidence()


@pytest.mark.parametrize(
    "contradiction",
    (
        "Docker build succeeded",
        "local Docker image build succeeded",
    ),
)
def test_root_evidence_contract_rejects_appended_task_12_quality_contradictions(
    monkeypatch: pytest.MonkeyPatch,
    contradiction: str,
) -> None:
    documents = {name: _read(name) for name in ("PLAN.md", "AGENT_LOG.md")}
    documents["PLAN.md"] = documents["PLAN.md"].replace(
        EXPECTED_TASK_12_QUALITY_REVIEW,
        f"{EXPECTED_TASK_12_QUALITY_REVIEW}; {contradiction}",
    )

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task12_completion_records_final_clean_local_evidence()


@pytest.mark.parametrize(
    ("path", "expected", "replacement"),
    (
        ("README.md", EXPECTED_PUBLIC_REPOSITORY_URL, "https://github.com/example/AI4SE"),
        ("PLAN.md", EXPECTED_INITIAL_CI_URL, "https://github.com/example/AI4SE/actions/runs/1"),
        ("AGENT_LOG.md", EXPECTED_INITIAL_CI_SHA, "deadbeef"),
        ("AGENT_LOG.md", EXPECTED_INITIAL_CI_CONCLUSION, "failure"),
        ("README.md", EXPECTED_HOSTED_URL, "https://example.onrender.com"),
        ("PLAN.md", EXPECTED_HOSTED_SHA, "deadbeef"),
        ("AGENT_LOG.md", EXPECTED_RENDER_DEPLOY_ID, "dep-example"),
        ("README.md", EXPECTED_HOSTED_TERMINAL_RESULT, "FAILED"),
        ("PLAN.md", EXPECTED_FINAL_CI_URL, "https://github.com/example/actions/runs/1"),
        ("README.md", EXPECTED_FINAL_CI_JOB_URL, "https://github.com/example/job/1"),
        ("PLAN.md", EXPECTED_ACCEPTANCE_TIME, "2026-07-30 00:00:00 GMT"),
        ("AGENT_LOG.md", EXPECTED_HOSTED_LIMITATION, "Production service."),
        (
            "README.md",
            EXPECTED_DASHBOARD_PROVENANCE,
            "The agent verified the Render dashboard through an authenticated browser.",
        ),
        (
            "PLAN.md",
            EXPECTED_ACCEPTANCE_PROVENANCE,
            "Hosted acceptance was user-supplied.",
        ),
        (
            "AGENT_LOG.md",
            EXPECTED_CI_PROVENANCE,
            "GitHub CI evidence was not independently verified.",
        ),
        ("README.md", EXPECTED_PROCESS_LOCAL_LIMITATION, "Task storage is durable."),
        (
            "PLAN.md",
            EXPECTED_DOCKER_LIMITATION,
            "Local Docker image build succeeded.",
        ),
        (
            "AGENT_LOG.md",
            EXPECTED_REVIEW_STATUS,
            "Task 13 final broad review complete.",
        ),
        ("README.md", EXPECTED_NO_LEAKAGE_RECORD, "Forbidden leakage was not checked."),
        ("PLAN.md", EXPECTED_NO_SELF_REFERENCE, "The final-audit commit passed CI."),
        ("README.md", EXPECTED_GUARDRAIL_EVIDENCE, ""),
        ("PLAN.md", EXPECTED_FEEDBACK_EVIDENCE, ""),
        ("AGENT_LOG.md", EXPECTED_PROGRESS_EVIDENCE, ""),
    ),
)
def test_task13_release_evidence_rejects_tampered_observed_values(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    expected: str,
    replacement: str,
) -> None:
    test_task13_final_release_audit_records_exact_evidence()
    documents = {
        name: _read(name)
        for name in ("README.md", "PLAN.md", "AGENT_LOG.md", "SPEC_PROCESS.md")
    }
    assert expected in documents[path]
    documents[path] = documents[path].replace(expected, replacement)

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task13_final_release_audit_records_exact_evidence()


@pytest.mark.parametrize(
    ("path", "marker", "contradiction"),
    (
        (
            "README.md",
            "## Credential Security",
            "This service has production availability and live provider mode.",
        ),
        (
            "README.md",
            "## Credential Security",
            "This paid service guarantees durable task storage.",
        ),
        (
            "PLAN.md",
            "**Files:**",
            "Task 3 review CLEAN; Task 13 final broad review complete.",
        ),
        (
            "PLAN.md",
            "**Files:**",
            "CI and Render deployed commit `06a5bf8`.",
        ),
        (
            "README.md",
            "## Credential Security",
            "This final audit commit passed CI and deployed to Render.",
        ),
        (
            "PLAN.md",
            "**Files:**",
            "The final-audit commit deployed with provider mode enabled.",
        ),
        (
            "AGENT_LOG.md",
            None,
            "Agent verified the Render dashboard through an authenticated browser.",
        ),
        (
            "AGENT_LOG.md",
            None,
            "Hosted acceptance was user-supplied.",
        ),
        (
            "README.md",
            "## Credential Security",
            "Conflicting repository: https://github.com/example/AI4SE.git.",
        ),
        (
            "PLAN.md",
            "**Files:**",
            "Conflicting CI SHA: `1111111111111111111111111111111111111111`.",
        ),
        (
            "AGENT_LOG.md",
            None,
            "Conflicting Render SHA: `2222222222222222222222222222222222222222`.",
        ),
        ("README.md", "## Credential Security", "Conflicting deploy ID: `dep-example`."),
        (
            "PLAN.md",
            "**Files:**",
            "Conflicting Render URL: https://example.onrender.com.",
        ),
        ("AGENT_LOG.md", None, "Conflicting terminal status: `FAILED`."),
        ("README.md", "## Credential Security", "Guardrail: `unexpected action allowed`."),
        ("PLAN.md", "**Files:**", "Feedback: `provider request`."),
        ("AGENT_LOG.md", None, "Progress: `read_file -> finish`."),
    ),
)
def test_task13_current_sections_reject_appended_contradictions(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    marker: str | None,
    contradiction: str,
) -> None:
    test_task13_final_release_audit_records_exact_evidence()
    documents = {
        name: _read(name)
        for name in ("README.md", "PLAN.md", "AGENT_LOG.md", "SPEC_PROCESS.md")
    }
    if marker is None:
        documents[path] = f"{documents[path]}\n{contradiction}\n"
    else:
        start_anchor = {
            "README.md": "### Render-compatible deployment",
            "PLAN.md": "### Task 13: Final Release and Hosted Demonstration Evidence",
        }[path]
        marker_index = documents[path].index(marker, documents[path].index(start_anchor))
        documents[path] = (
            documents[path][:marker_index]
            + f"{contradiction}\n\n"
            + documents[path][marker_index:]
        )

    monkeypatch.setitem(globals(), "_read", documents.__getitem__)
    with pytest.raises(AssertionError):
        test_task13_final_release_audit_records_exact_evidence()


@pytest.mark.parametrize(
    ("expected", "replacement"),
    (
        ("- Model: `gpt-5.6-sol`", "- Model: unavailable"),
        (
            "- Context supplied: only `SPEC.md` and `PLAN.md` paths",
            "- Context supplied: conversation history and repository",
        ),
        ("### Actual Task 1 Findings", "### Task 1 Findings unavailable"),
        ("Divergent interpretations:", "Interpretations unavailable:"),
        ("### Corrections Made", "### Corrections pending"),
    ),
)
def test_task0_process_record_rejects_missing_audit_facts(
    expected: str,
    replacement: str,
) -> None:
    process_record = _read("SPEC_PROCESS.md")
    _validate_task0_process_record(process_record)
    assert expected in process_record

    with pytest.raises(AssertionError):
        _validate_task0_process_record(process_record.replace(expected, replacement))


@pytest.mark.parametrize("task", tuple(EXPECTED_TASK_3_TO_10_ROWS))
def test_root_evidence_rejects_task_3_to_10_commit_tampering(task: str) -> None:
    plan = _read("PLAN.md")
    agent_log = _read("AGENT_LOG.md")
    _validate_root_evidence(plan, agent_log)
    commit = re.findall(r"\b[0-9a-f]{7,40}\b", EXPECTED_TASK_3_TO_10_ROWS[task][4])[0]
    assert commit in plan
    with pytest.raises(AssertionError):
        _validate_root_evidence(plan.replace(f"`{commit}`", "`deadbee`", 1), agent_log)


@pytest.mark.parametrize(
    ("expected", "replacement"),
    (
        ("prior five-round breaker resolved by approved contract amendment", "review CLEAN"),
        ("prior five-round breaker resolved by approved lifecycle amendment", "review CLEAN"),
        ("`/root/task8_review`: clean after fix round 4", "review unavailable"),
    ),
)
def test_root_evidence_rejects_erased_task_3_to_10_review_history(
    expected: str, replacement: str
) -> None:
    plan = _read("PLAN.md")
    agent_log = _read("AGENT_LOG.md")
    _validate_root_evidence(plan, agent_log)
    assert expected in plan
    with pytest.raises(AssertionError):
        _validate_root_evidence(plan.replace(expected, replacement), agent_log)


def test_root_evidence_rejects_reordered_task_3_to_10_chronology() -> None:
    plan = _read("PLAN.md")
    agent_log = _read("AGENT_LOG.md")
    first = "## 2026-07-28 Task 3 revalidation ruling"
    second = "## 2026-07-28 Task 3 implementation and fix round 1"
    _validate_root_evidence(plan, agent_log)
    with pytest.raises(AssertionError):
        _validate_root_evidence(plan, agent_log.replace(first, "TEMP", 1).replace(second, first, 1).replace("TEMP", second, 1))


@pytest.mark.parametrize("expected", EXPECTED_TASK_0_SUBSTANTIVE_FACTS)
def test_task0_process_record_rejects_fabricated_substantive_details(expected: str) -> None:
    process_record = _read("SPEC_PROCESS.md")
    _validate_task0_process_record(process_record)
    assert expected in process_record
    with pytest.raises(AssertionError):
        _validate_task0_process_record(process_record.replace(expected, "fabricated detail", 1))


def test_root_evidence_contract_does_not_require_git_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_git(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("root evidence validation must not invoke Git")

    monkeypatch.setattr(subprocess, "run", unavailable_git)
    _validate_root_evidence(_read("PLAN.md"), _read("AGENT_LOG.md"))


def test_required_artifacts_and_readme_headings_exist() -> None:
    required_paths = (
        "README.md",
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        "Dockerfile",
        ".dockerignore",
    )
    assert all((REPOSITORY_ROOT / path).is_file() for path in required_paths)

    readme = _read("README.md")
    for heading in (
        "## Installation",
        "## Running",
        "## Distribution",
        "## Credential Security",
        "## Project Structure",
        "## Safety Boundaries",
        "## Known Limitations",
    ):
        assert heading in readme


def test_readme_documents_safe_local_and_portable_delivery_limits() -> None:
    readme = _read("README.md")
    for text in (
        "keyring-first",
        "PYQUALITY_API_KEY",
        "plaintext",
        "pytest can execute repository code",
        "not an operating-system sandbox",
        "local SQLite and audit",
        "docker build -t pyquality-harness .",
        "docker run --rm -p 8000:8000 pyquality-harness",
        "### Render-compatible deployment",
        EXPECTED_HOSTED_URL,
        EXPECTED_HOSTED_LIMITATION,
    ):
        assert text in readme


def test_readme_documents_exact_local_webui_command() -> None:
    assert "pyquality serve --host 127.0.0.1 --port 8000" in _read("README.md").splitlines()


def test_readme_ordinary_wheel_install_includes_runtime_dependencies() -> None:
    readme_lines = _read("README.md").splitlines()
    wheel_install = (
        "python -m pip install dist\\pyquality_harness-0.1.0-py3-none-any.whl"
    )
    assert wheel_install in readme_lines
    for index, line in enumerate(readme_lines):
        if "--no-deps" not in line:
            continue
        context = " ".join(readme_lines[max(0, index - 3) : index + 4]).lower()
        assert "controlled verification" in context
        assert "system-site-packages" in context


def test_ci_files_define_the_course_commands_and_triggers() -> None:
    github_ci = _read(".github/workflows/ci.yml")
    assert re.search(r"(?m)^on:\s*\n\s+push:\s*\n\s+pull_request:", github_ci)
    assert "python-version: \"3.12\"" in github_ci
    for command in (
        "pytest -q",
        "ruff check src tests",
        "python -m build",
        "docker build",
    ):
        assert command in github_ci
    assert ".[dev]" in github_ci

    gitlab_ci = _read(".gitlab-ci.yml")
    assert re.search(r"(?m)^unit-test:\s*$", gitlab_ci)
    assert "image: python:3.12-slim" in gitlab_ci
    assert "-e \".[dev]\"" in gitlab_ci
    assert "pytest -q" in gitlab_ci


def test_pyproject_declares_buildable_python_package_contract() -> None:
    project = tomllib.loads(_read("pyproject.toml"))
    assert project["project"]["requires-python"] == ">=3.12"
    assert project["build-system"]["build-backend"] == "hatchling.build"
    assert any(requirement.startswith("hatchling>=1.25") for requirement in project["build-system"]["requires"])
    assert project["project"]["scripts"]["pyquality"] == "pyquality.cli:main"
    assert any(
        dependency.startswith("build>=1.2")
        for dependency in project["project"]["optional-dependencies"]["dev"]
    )
    assert any(
        dependency.startswith("hatchling>=1.25")
        for dependency in project["project"]["optional-dependencies"]["dev"]
    )
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/pyquality"]


def test_wheel_contains_runtime_assets_but_no_development_or_data_residue(tmp_path: Path) -> None:
    distribution_directory = tmp_path / "dist"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        env=environment,
    )
    wheel_path = next(distribution_directory.glob("*.whl"))
    with zipfile.ZipFile(wheel_path) as wheel:
        contents = set(wheel.namelist())
        metadata = wheel.read(
            next(name for name in contents if name.endswith(".dist-info/METADATA"))
        ).decode("utf-8")

    assert {
        "pyquality/web/templates/approval.html",
        "pyquality/web/templates/base.html",
        "pyquality/web/templates/settings.html",
        "pyquality/web/templates/task_detail.html",
        "pyquality/web/templates/tasks_new.html",
        "pyquality/demo_fixture/__init__.py",
        "pyquality/demo_fixture/calculator.py",
        "pyquality/demo_fixture/pyproject.toml",
        "pyquality/demo_fixture/test_calculator.py",
    } <= contents
    prohibited_prefixes = ("tests/", ".git/", ".superpowers/")
    assert not any(name.startswith(prohibited_prefixes) for name in contents)
    assert not any(
        name.endswith((".db", ".sqlite", ".log"))
        or "/audit/" in name
        or "/cache/" in name
        for name in contents
    )
    requirement_values = Parser().parsestr(metadata).get_all("Requires-Dist", [])
    runtime_names = {
        canonicalize_name(parsed.name)
        for value in requirement_values
        if (
            (parsed := Requirement(value)).marker is None
            or parsed.marker.evaluate({"extra": ""})
        )
    }
    assert {canonicalize_name("pytest"), canonicalize_name("ruff")} <= runtime_names


def test_copy_sdist_source_copies_explicit_inputs_without_traversing_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_root = tmp_path / "fixture-repository"
    (fixture_root / "src" / "pyquality" / "web" / "templates").mkdir(parents=True)
    (fixture_root / "src" / "pyquality" / "demo_fixture").mkdir()
    (fixture_root / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    (fixture_root / "README.md").write_text("fixture readme\n", encoding="utf-8")
    (fixture_root / "src" / "pyquality" / "public_demo_worker.py").write_text(
        "worker = True\n", encoding="utf-8"
    )
    (fixture_root / "src" / "pyquality" / "web" / "templates" / "base.html").write_text(
        "<main>fixture</main>\n", encoding="utf-8"
    )
    (fixture_root / "src" / "pyquality" / "demo_fixture" / "calculator.py").write_text(
        "def add(left, right): return left + right\n", encoding="utf-8"
    )
    (fixture_root / ".pytest-task-residue").mkdir()
    (fixture_root / ".pytest-task-residue" / "locked.txt").write_text(
        "unrelated\n", encoding="utf-8"
    )
    source_root = tmp_path / "source"
    real_copytree = shutil.copytree

    def copy_only_src(source: str | Path, destination: str | Path, **kwargs: object) -> Path:
        assert Path(source) == fixture_root / "src"
        monkeypatch.setattr(shutil, "copytree", real_copytree)
        return real_copytree(source, destination, **kwargs)

    monkeypatch.setitem(globals(), "REPOSITORY_ROOT", fixture_root)
    monkeypatch.setattr(shutil, "copytree", copy_only_src)

    _copy_sdist_source(source_root)

    assert (source_root / "pyproject.toml").is_file()
    assert (source_root / "README.md").is_file()
    assert (source_root / "src" / "pyquality" / "public_demo_worker.py").is_file()
    assert (source_root / "src" / "pyquality" / "web" / "templates" / "base.html").is_file()
    assert (source_root / "src" / "pyquality" / "demo_fixture" / "calculator.py").is_file()
    assert not (source_root / ".pytest-task-residue").exists()


def test_copy_sdist_source_copies_directly_declared_license_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_root = tmp_path / "fixture-repository"
    (fixture_root / "src").mkdir(parents=True)
    (fixture_root / "pyproject.toml").write_text(
        "[project]\nname = 'fixture'\nlicense = {file = 'COPYING'}\n",
        encoding="utf-8",
    )
    (fixture_root / "README.md").write_text("fixture readme\n", encoding="utf-8")
    (fixture_root / "COPYING").write_text("fixture license\n", encoding="utf-8")
    monkeypatch.setitem(globals(), "REPOSITORY_ROOT", fixture_root)

    _copy_sdist_source(tmp_path / "source")

    assert (tmp_path / "source" / "COPYING").read_text(encoding="utf-8") == "fixture license\n"


def test_sdist_excludes_development_and_local_data_but_keeps_runtime_inputs(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    _copy_sdist_source(source_root)
    sentinel = source_root / ".venv-sentinel" / "marker"
    sentinel.parent.mkdir()
    sentinel.write_text("must never ship\n", encoding="utf-8")
    distribution_directory = tmp_path / "dist"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(distribution_directory),
        ],
        cwd=source_root,
        check=True,
    )
    with tarfile.open(next(distribution_directory.glob("*.tar.gz"))) as sdist:
        contents = sdist.getnames()

    assert any(name.endswith("/pyproject.toml") for name in contents)
    assert any(name.endswith("/README.md") for name in contents)
    assert any(name.endswith("/src/pyquality/web/templates/base.html") for name in contents)
    assert any(name.endswith("/src/pyquality/demo_fixture/calculator.py") for name in contents)
    assert not any(name.endswith("/.venv-sentinel/marker") for name in contents)
    assert not any(
        part.startswith(".venv")
        for name in contents
        for part in Path(name).parts[1:]
    )
    assert not any(
        (relative_parts := Path(name).parts[1:])[:1] in {("examples",), ("tests",)}
        or any(part in {".git", ".superpowers", "__pycache__"} for part in relative_parts)
        or name.endswith((".db", ".sqlite", ".sqlite3", ".log"))
        or "/audit/" in name
        or "/cache/" in name
        for name in contents
    )


def test_dockerfile_builds_and_runs_only_the_public_mock_distribution() -> None:
    dockerfile = _read("Dockerfile")
    assert re.search(r"(?mi)^FROM\s+python:3\.12-slim\s+AS\s+builder\s*$", dockerfile)
    assert re.search(r"(?mi)^FROM\s+python:3\.12-slim\s+AS\s+runtime\s*$", dockerfile)
    assert "python -m build --wheel --no-isolation" in dockerfile
    assert re.search(r"pip install --no-cache-dir /tmp/dist/.*\.whl", dockerfile)
    assert "ENV PYQUALITY_MODE=public_mock" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert (
        'CMD ["pyquality", "serve", "--host", "0.0.0.0", "--port", "8000", "--public-mock"]'
        in dockerfile
    )
    assert not re.search(r"(?i)\b(ARG|ENV)\b.*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", dockerfile)
    assert "pip install -e" not in dockerfile
    assert "COPY tests" not in dockerfile
    assert "provider" not in dockerfile.lower()


def test_dockerignore_excludes_development_and_sensitive_local_data() -> None:
    ignored_paths = {
        line.strip()
        for line in _read(".dockerignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {
        ".git",
        ".superpowers",
        ".worktrees",
        "__pycache__/",
        ".pytest_cache/",
        ".ruff_cache/",
        "tests/",
        "dist/",
        "build/",
        "*.db*",
        "*.db",
        "*.sqlite",
        "*.sqlite3",
        "*.log",
        "audit/",
        "cache/",
        "AI4SE_Final_Project_A_Coding_Agent_Harness.md",
        "通用要求.md",
    } <= ignored_paths
    assert "pyproject.toml" not in ignored_paths
    assert "src/" not in ignored_paths
