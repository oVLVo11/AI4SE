from __future__ import annotations

from pathlib import Path

from pyquality.demo import run_demo
from pyquality.domain.models import TaskStatus


def test_demo_proves_guardrail_feedback_progress_and_success(tmp_path: Path) -> None:
    """Removing any claimed mechanism evidence makes the bundled demo untrustworthy."""
    report = run_demo(tmp_path)

    assert report.denied_action.attempted is True
    assert report.denied_action.dispatch_count == 0
    assert report.action_order == (
        "read_file",
        "apply_patch",
        "apply_patch",
        "finish",
    )
    assert report.first_failure_category == "assertion"
    assert report.model_saw_first_failure is True
    assert report.first_patch_digest != report.second_patch_digest
    assert report.first_fingerprint != report.second_fingerprint
    assert report.final_status is TaskStatus.SUCCEEDED
