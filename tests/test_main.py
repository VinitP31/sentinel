"""run_pipeline timing instrumentation tests.

No live AWS calls and no real AI call — every collector, explain_findings,
and render_report call is mocked or replaced with existing fixtures. This
suite is about the timing instrumentation only: it does not re-verify
finding/report correctness, which is already covered elsewhere (test_rules,
test_normalize_iam, test_graph_build, test_report_build, etc).
"""

import json
from pathlib import Path
from unittest.mock import patch

from src import main
from src.util.status import ok

FIXTURE_DIR = Path(__file__).parent / "fixtures"

EXPECTED_STAGE_NAMES = {
    "IAM Configuration Collection",
    "IAM Normalization",
    "Group Inheritance",
    "Last Accessed Evidence",
    "Relationship Graph",
    "CloudTrail Event History",
    "Deterministic Security Analysis",
    "Access Analyzer & Evidence Package",
    "AI Security Explanation",
}


def _raw_iam() -> dict:
    return json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())


def _last_accessed() -> dict:
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


def _identity() -> dict:
    return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test", "region": "us-east-1"}


def _cloudtrail() -> dict:
    return {
        "region": "us-east-1",
        "evidence_window": {
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-02T00:00:00+00:00",
            "lookback_days": 90,
        },
        "events": [],
    }


def _run_pipeline_with_mocks(tmp_path, monkeypatch, raw_iam_status=None, progress_callback=None):
    # run_pipeline prints paths via relative_to(config.PROJECT_ROOT) for
    # human-readable terminal output — a pre-existing behavior, unrelated to
    # this instrumentation. tmp_path isn't under the real project root, so
    # PROJECT_ROOT is redirected for the duration of this test only.
    monkeypatch.setattr(main.config, "PROJECT_ROOT", tmp_path)

    raw_iam = _raw_iam()
    last_accessed_data = _last_accessed()
    last_accessed_statuses = [ok(f"last_accessed:{arn}", {"services": len(v["services_last_accessed"])}) for arn, v in last_accessed_data.items()]
    iam_status = raw_iam_status or ok("iam_configuration", {"users": len(raw_iam.get("UserDetailList", []))}, 1)

    with (
        patch("src.main.iam_collector.collect", return_value=(raw_iam, iam_status)),
        patch("src.main.last_accessed_collector.collect", return_value=(last_accessed_data, last_accessed_statuses)),
        patch("src.main.cloudtrail_collector.collect", return_value=(_cloudtrail(), ok("cloudtrail_event_history", {"events": 0}, 1))),
        patch("src.main.access_analyzer_collector.collect", return_value=({"analyzers": [], "findings": []}, ok("access_analyzer", {"analyzers": 0, "findings": 0}))),
        patch("src.main.explain_findings", return_value=([], ok("ai_explanations", {"explanations": 0}))),
        patch("src.main.render_report", return_value=tmp_path / "REPORT.html"),
    ):
        return main.run_pipeline(
            session=None, identity=_identity(), output_dir=tmp_path, progress_callback=progress_callback
        )


def test_every_executed_stage_gets_timing_information(tmp_path, monkeypatch):
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)

    recorded_names = {entry["stage"] for entry in result["timings"]["stages"]}
    assert recorded_names == EXPECTED_STAGE_NAMES


def test_durations_are_non_negative(tmp_path, monkeypatch):
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)

    for entry in result["timings"]["stages"]:
        assert entry["duration_seconds"] >= 0
    assert result["timings"]["total_duration_seconds"] >= 0


def test_total_duration_is_present_and_at_least_the_sum_of_stages(tmp_path, monkeypatch):
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)

    total = result["timings"]["total_duration_seconds"]
    stage_sum = sum(entry["duration_seconds"] for entry in result["timings"]["stages"])
    assert total is not None
    assert total >= stage_sum


def test_timing_does_not_change_findings(tmp_path, monkeypatch):
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)

    findings_path = result["findings_path"]
    findings = json.loads(findings_path.read_text())
    for finding in findings:
        assert "duration_seconds" not in finding
        assert "timings" not in finding
        assert set(finding.keys()) == {"rule", "principal", "policy_id", "attribution", "detail"} | (
            {"evidence_window"} if finding["rule"] == "potentially_unused_access" else set()
        )


def test_existing_finding_count_and_completeness_unchanged(tmp_path, monkeypatch):
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)

    assert result["complete"] is True
    assert result["finding_count"] == len(json.loads(result["findings_path"].read_text()))


def test_partial_failure_still_records_iam_collection_timing(tmp_path, monkeypatch):
    failed_status = ok("iam_configuration", {"users": 0}, 0)
    failed_status.succeeded = False
    failed_status.error = "simulated AccessDenied"

    result = _run_pipeline_with_mocks(tmp_path, monkeypatch, raw_iam_status=failed_status)

    assert result["complete"] is False
    assert result["timings"]["stages"] == [{"stage": "IAM Configuration Collection", "duration_seconds": result["timings"]["stages"][0]["duration_seconds"]}]
    assert result["timings"]["stages"][0]["duration_seconds"] >= 0
    assert result["timings"]["total_duration_seconds"] >= 0


# --- progress_callback -------------------------------------------------


def test_progress_callback_receives_running_events_for_every_stage(tmp_path, monkeypatch):
    events = []
    _run_pipeline_with_mocks(
        tmp_path,
        monkeypatch,
        progress_callback=lambda *args, **kwargs: events.append((args, kwargs)),
    )

    running_stage_names = {args[2] for args, kwargs in events if kwargs.get("status") == "running"}
    assert running_stage_names == EXPECTED_STAGE_NAMES


def test_progress_callback_receives_completed_events_with_duration(tmp_path, monkeypatch):
    events = []
    _run_pipeline_with_mocks(
        tmp_path,
        monkeypatch,
        progress_callback=lambda *args, **kwargs: events.append((args, kwargs)),
    )

    completed = {args[2]: kwargs for args, kwargs in events if kwargs.get("status") == "completed"}
    assert set(completed) == EXPECTED_STAGE_NAMES
    for stage_name, kwargs in completed.items():
        assert kwargs["duration_seconds"] >= 0


def test_progress_callback_receives_failed_event_for_failed_stage(tmp_path, monkeypatch):
    events = []
    failed_status = ok("iam_configuration", {"users": 0}, 0)
    failed_status.succeeded = False
    failed_status.error = "simulated AccessDenied"

    _run_pipeline_with_mocks(
        tmp_path,
        monkeypatch,
        raw_iam_status=failed_status,
        progress_callback=lambda *args, **kwargs: events.append((args, kwargs)),
    )

    failed_events = [(args, kwargs) for args, kwargs in events if kwargs.get("status") == "failed"]
    assert len(failed_events) == 1
    args, kwargs = failed_events[0]
    assert args[2] == "IAM Configuration Collection"
    assert kwargs["duration_seconds"] >= 0


def test_progress_callback_carries_stage_number_and_total(tmp_path, monkeypatch):
    events = []
    _run_pipeline_with_mocks(
        tmp_path,
        monkeypatch,
        progress_callback=lambda *args, **kwargs: events.append((args, kwargs)),
    )

    for (stage_number, total_stages, stage_name), kwargs in events:
        assert isinstance(stage_number, int)
        assert total_stages == main.TOTAL_PIPELINE_STAGES


def test_no_progress_callback_means_no_crash_and_unchanged_result(tmp_path, monkeypatch):
    """Existing callers that never pass progress_callback must see identical behavior."""
    result = _run_pipeline_with_mocks(tmp_path, monkeypatch)
    assert result["complete"] is True
