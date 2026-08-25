"""Multi-account orchestration tests.

No live AWS calls and no real pipeline run — auth.assume_role, auth.verify_identity,
run_pipeline, and organizations_collector.collect are all mocked. Covers per-account
success/failure isolation, aggregate counts, findings tagging, and the combined
result's persistence to disk (config.OUTPUT_DIR is redirected to tmp_path so
tests never write into the real project output/ tree).
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src import orchestrator
from src.aws import auth
from src.util.status import ok


def make_session():
    return MagicMock()


PROD_ARN = f"arn:aws:iam::328865868092:role/{orchestrator.ROLE_NAME}"
DEV_ARN = f"arn:aws:iam::587762853586:role/{orchestrator.ROLE_NAME}"


# --- audit_account --------------------------------------------------------


def test_audit_account_success():
    base_session = make_session()
    target_session = make_session()
    identity = {"account_id": "328865868092", "arn": "arn:...:assumed-role/AuditReadOnlyRole/x", "region": "us-east-1"}
    pipeline_result = {"finding_count": 6, "findings_path": "/tmp/findings.json", "complete": True}

    with patch("src.orchestrator.auth.assume_role", return_value=target_session) as mock_assume, \
         patch("src.orchestrator.auth.verify_identity", return_value=identity), \
         patch("src.orchestrator.run_pipeline", return_value=pipeline_result) as mock_pipeline:
        result = orchestrator.audit_account(base_session, "PROD", "328865868092")

    mock_assume.assert_called_once_with(base_session, PROD_ARN)
    mock_pipeline.assert_called_once()
    assert result == {
        "account_label": "PROD",
        "account_id": "328865868092",
        "status": "success",
        "finding_count": 6,
        "pipeline_result": pipeline_result,
    }


def test_audit_account_authentication_failure():
    base_session = make_session()

    with patch("src.orchestrator.auth.assume_role", side_effect=auth.AuthError("Could not assume role: AccessDenied")):
        result = orchestrator.audit_account(base_session, "DEV", "587762853586")

    assert result["status"] == "failed"
    assert result["failure_stage"] == "authentication"
    assert result["account_label"] == "DEV"
    assert result["account_id"] == "587762853586"
    assert "AccessDenied" in result["error"]


def test_audit_account_pipeline_failure_after_successful_assume_role():
    base_session = make_session()
    target_session = make_session()
    identity = {"account_id": "328865868092", "arn": "arn:...", "region": "us-east-1"}

    with patch("src.orchestrator.auth.assume_role", return_value=target_session), \
         patch("src.orchestrator.auth.verify_identity", return_value=identity), \
         patch("src.orchestrator.run_pipeline", side_effect=RuntimeError("unexpected collection error")):
        result = orchestrator.audit_account(base_session, "PROD", "328865868092")

    assert result["status"] == "failed"
    assert result["failure_stage"] == "collection"
    assert "unexpected collection error" in result["error"]


def test_one_account_failure_does_not_prevent_the_other():
    base_session = make_session()
    identity = {"account_id": "587762853586", "arn": "arn:...", "region": "us-east-1"}
    pipeline_result = {"finding_count": 3, "findings_path": "/tmp/dev_findings.json", "complete": True}

    def fake_assume_role(session, role_arn):
        if role_arn == PROD_ARN:
            raise auth.AuthError("Could not assume role: AccessDenied")
        return make_session()

    with patch("src.orchestrator.auth.assume_role", side_effect=fake_assume_role), \
         patch("src.orchestrator.auth.verify_identity", return_value=identity), \
         patch("src.orchestrator.run_pipeline", return_value=pipeline_result):
        prod_result = orchestrator.audit_account(base_session, "PROD", "328865868092")
        dev_result = orchestrator.audit_account(base_session, "DEV", "587762853586")

    assert prod_result["status"] == "failed"
    assert dev_result["status"] == "success"


# --- audit_all_accounts ----------------------------------------------------


def _mgmt_session_with_account(account_id="957728667615"):
    session = make_session()
    session.client.return_value.get_caller_identity.return_value = {"Account": account_id}
    return session


def test_audit_all_accounts_aggregate_success(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)
    base_session = _mgmt_session_with_account()

    prod_findings = [{"rule": "broad_permission", "principal": {"name": "AdminRole"}}]
    dev_findings = [{"rule": "potentially_unused_access", "principal": {"name": "Bob"}}]
    prod_path = tmp_path / "prod_findings.json"
    dev_path = tmp_path / "dev_findings.json"
    prod_path.write_text(json.dumps(prod_findings))
    dev_path.write_text(json.dumps(dev_findings))

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        path = prod_path if label == "PROD" else dev_path
        return {
            "account_label": label,
            "account_id": account_id,
            "status": "success",
            "finding_count": 1,
            "pipeline_result": {"finding_count": 1, "findings_path": str(path), "complete": True},
        }

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        aggregate = orchestrator.audit_all_accounts(base_session)

    assert aggregate["management_account_id"] == "957728667615"
    assert aggregate["accounts_succeeded"] == 2
    assert aggregate["accounts_failed"] == 0
    assert aggregate["total_findings"] == 2
    assert len(aggregate["findings"]) == 2
    assert aggregate["total_findings"] == len(aggregate["findings"])


def test_audit_all_accounts_mixed_success_and_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)
    base_session = _mgmt_session_with_account()

    dev_findings = [{"rule": "potentially_unused_access", "principal": {"name": "Bob"}}]
    dev_path = tmp_path / "dev_findings.json"
    dev_path.write_text(json.dumps(dev_findings))

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        if label == "PROD":
            return {
                "account_label": "PROD",
                "account_id": account_id,
                "status": "failed",
                "failure_stage": "authentication",
                "error": "Could not assume role: AccessDenied",
            }
        return {
            "account_label": "DEV",
            "account_id": account_id,
            "status": "success",
            "finding_count": 1,
            "pipeline_result": {"finding_count": 1, "findings_path": str(dev_path), "complete": True},
        }

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        aggregate = orchestrator.audit_all_accounts(base_session)

    assert aggregate["accounts_succeeded"] == 1
    assert aggregate["accounts_failed"] == 1
    assert aggregate["total_findings"] == 1
    assert aggregate["findings"][0]["account_name"] == "DEV"


# --- _tag_findings ----------------------------------------------------------


def test_tag_findings_adds_account_id_and_name(tmp_path):
    findings = [
        {"rule": "broad_permission", "principal": {"name": "AdminRole"}, "policy_id": "p1",
         "attribution": {"attachment_type": "inline"}, "detail": "..."},
    ]
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings))

    tagged = orchestrator._tag_findings(path, "328865868092", "PROD")

    assert tagged[0]["account_id"] == "328865868092"
    assert tagged[0]["account_name"] == "PROD"


def test_tag_findings_preserves_all_original_fields(tmp_path):
    findings = [
        {"rule": "potentially_unused_access", "principal": {"id": "arn:...", "name": "Bob", "type": "user"},
         "policy_id": "arn:...", "attribution": {"attachment_type": "group_inherited", "source_group_name": "Auditors"},
         "detail": "No corresponding activity observed in the collected evidence."},
    ]
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(findings))

    tagged = orchestrator._tag_findings(path, "587762853586", "DEV")

    original = findings[0]
    for key, value in original.items():
        assert tagged[0][key] == value


def test_tag_findings_does_not_mutate_source_file(tmp_path):
    findings = [{"rule": "broad_permission", "principal": {"name": "AdminRole"}}]
    path = tmp_path / "findings.json"
    original_text = json.dumps(findings)
    path.write_text(original_text)

    orchestrator._tag_findings(path, "328865868092", "PROD")

    assert path.read_text() == original_text
    assert "account_id" not in json.loads(path.read_text())[0]


def test_total_findings_equals_length_of_combined_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)
    base_session = _mgmt_session_with_account()

    prod_findings = [{"rule": "broad_permission"}, {"rule": "administrative_access"}]
    dev_findings = [{"rule": "potentially_unused_access"}]
    prod_path = tmp_path / "prod_findings.json"
    dev_path = tmp_path / "dev_findings.json"
    prod_path.write_text(json.dumps(prod_findings))
    dev_path.write_text(json.dumps(dev_findings))

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        path = prod_path if label == "PROD" else dev_path
        return {
            "account_label": label,
            "account_id": account_id,
            "status": "success",
            "finding_count": len(json.loads(path.read_text())),
            "pipeline_result": {"findings_path": str(path)},
        }

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        aggregate = orchestrator.audit_all_accounts(base_session)

    assert aggregate["total_findings"] == 3
    assert len(aggregate["findings"]) == 3
    assert aggregate["total_findings"] == len(aggregate["findings"])


# --- combined_findings.json persistence -------------------------------------


def test_audit_all_accounts_persists_combined_findings_json(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)

    base_session = _mgmt_session_with_account()

    prod_findings = [{"rule": "broad_permission"}]
    dev_findings = [{"rule": "potentially_unused_access"}]
    prod_path = tmp_path / "prod_findings.json"
    dev_path = tmp_path / "dev_findings.json"
    prod_path.write_text(json.dumps(prod_findings))
    dev_path.write_text(json.dumps(dev_findings))

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        path = prod_path if label == "PROD" else dev_path
        return {
            "account_label": label,
            "account_id": account_id,
            "status": "success",
            "finding_count": len(json.loads(path.read_text())),
            "pipeline_result": {"findings_path": str(path)},
        }

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        aggregate = orchestrator.audit_all_accounts(base_session)

    combined_path = tmp_path / "combined_findings.json"
    assert combined_path.exists()

    loaded = json.loads(combined_path.read_text())
    assert loaded["total_findings"] == len(loaded["findings"])
    assert loaded == aggregate

    tags = {f["account_name"] for f in loaded["findings"]}
    assert tags == {"PROD", "DEV"}


# --- progress_callback ------------------------------------------------------


def test_audit_account_forwards_progress_callback_tagged_with_account_label():
    base_session = make_session()
    target_session = make_session()
    identity = {"account_id": "328865868092", "arn": "arn:...", "region": "us-east-1"}
    events = []

    def fake_run_pipeline(session, identity, output_dir, progress_callback=None):
        progress_callback(2, 9, "IAM Configuration Collection", status="running")
        progress_callback(2, 9, "IAM Configuration Collection", status="completed", duration_seconds=1.23)
        return {"finding_count": 0, "findings_path": "/tmp/f.json"}

    with patch("src.orchestrator.auth.assume_role", return_value=target_session), \
         patch("src.orchestrator.auth.verify_identity", return_value=identity), \
         patch("src.orchestrator.run_pipeline", side_effect=fake_run_pipeline):
        orchestrator.audit_account(
            base_session, "PROD", "328865868092",
            progress_callback=lambda *a, **kw: events.append((a, kw)),
        )

    assert len(events) == 2
    for args, kwargs in events:
        assert kwargs["account_label"] == "PROD"


def test_audit_all_accounts_fires_account_transition_events(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)
    base_session = _mgmt_session_with_account()
    events = []

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        return {"account_label": label, "account_id": account_id, "status": "success",
                "finding_count": 0, "pipeline_result": {}}

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        orchestrator.audit_all_accounts(base_session, progress_callback=lambda *a, **kw: events.append((a, kw)))

    account_transition_labels = [kw["account_label"] for a, kw in events if a[0] is None]
    assert account_transition_labels == ["PROD", "DEV"]


def test_no_progress_callback_is_still_optional_and_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "OUTPUT_DIR", tmp_path)
    base_session = _mgmt_session_with_account()

    def fake_audit_account(base_session, label, account_id, progress_callback=None):
        return {"account_label": label, "account_id": account_id, "status": "success",
                "finding_count": 0, "pipeline_result": {}}

    with patch("src.orchestrator.organizations_collector.collect", return_value=({}, ok("organizations", {"accounts": 3}))), \
         patch("src.orchestrator.audit_account", side_effect=fake_audit_account):
        aggregate = orchestrator.audit_all_accounts(base_session)

    assert aggregate["accounts_succeeded"] == 2
