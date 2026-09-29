"""Collection Evidence feature tests: JSON builder + PDF renderer, for both
providers, plus pipeline-level integration proving the new artifacts appear
without changing existing collection, normalization, finding, or report
behavior.

Fixtures/mocks only - no live AWS or vCenter call in this file. Real vCenter
sandbox verification (spot-checking a real run's collection_evidence.json
against the live sandbox) is a separate, manual step - see the session
report for what was and wasn't run.
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from reportlab.platypus import KeepTogether, Paragraph, Table

from src import main
from src.evidence import evidence_report
from src.evidence.collection_evidence import build_aws_collection_evidence, build_vcenter_collection_evidence
from src.evidence.evidence_report import render_collection_evidence_pdf
from src.normalize.iam import normalize as normalize_iam
from src.util.io import write_json
from src.util.status import failed, ok
from src.vcenter import pipeline as vcenter_pipeline
from src.vcenter.normalize import normalize as normalize_vcenter

FIXTURE_DIR = Path(__file__).parent / "fixtures"

# --- AWS fixtures (reuse the same fixture files test_main.py already uses) -


def _raw_iam() -> dict:
    return json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())


def _last_accessed() -> dict:
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


def _identity() -> dict:
    return {
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:user/test",
        "user_id": "AID000EXAMPLE",
        "region": "us-east-1",
    }


def _cloudtrail() -> dict:
    return {
        "region": "us-east-1",
        "evidence_window": {"start_time": "2026-01-01T00:00:00+00:00", "end_time": "2026-01-02T00:00:00+00:00", "lookback_days": 90},
        "events": [
            {
                "EventName": "ListBuckets",
                "EventTime": "2026-01-01T12:00:00+00:00",
                "EventSource": "s3.amazonaws.com",
                "CloudTrailEvent": '{"userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice"}}',
                "attributed_principal_arn": "arn:aws:iam::123456789012:user/alice",
            }
        ],
    }


def _analyzer() -> dict:
    return {
        "analyzers": [
            {"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/POC-External-Access", "name": "POC-External-Access", "type": "ACCOUNT", "status": "ACTIVE"}
        ],
        "findings": [],
    }


def _statuses() -> list:
    return [ok("iam_configuration", {"users": 3}, 1), ok("cloudtrail_event_history", {"events": 1}, 1), failed("access_analyzer", "boom")]


# --- vCenter fixtures (small, self-contained - shaped like real collector
# output, mirrors the FAKE_INVENTORY/FAKE_AUTHORIZATION pattern already used
# in tests/test_vcenter_pipeline.py) --------------------------------------


def _vcenter_inventory() -> dict:
    return {
        "datacenter": [{"id": "datacenter-2001", "type": "datacenter", "name": "DC-Lab", "parent": None}],
        "folder": [{"id": "group-d1", "type": "folder", "name": "Datacenters", "parent": None}],
        "cluster": [{"id": "domain-c1007", "type": "cluster", "name": "Cluster-A", "parent": None}],
        "host": [],
        "vm": [],
        "resource_pool": [{"id": "resgroup-1008", "type": "resource_pool", "name": "Resources", "parent": None}],
    }


_DIRECT_PERMISSION = {
    "principal": "VSPHERE.LOCAL\\platform-admins",
    "group": True,
    "roleId": 579378617,
    "role_name": "DangerousRole",
    "propagate": True,
    "entity_type": "cluster",
    "entity_id": "domain-c1007",
}
_INHERITED_PERMISSION = {
    "principal": "VSPHERE.LOCAL\\Administrator",
    "group": False,
    "roleId": -1,
    "role_name": "Admin",
    "propagate": True,
    "entity_type": "folder",
    "entity_id": "group-d1",
}


def _vcenter_authorization() -> dict:
    return {
        "roles": {
            -1: {"roleId": -1, "name": "Admin", "system": True, "label": "Admin", "privilege_ids": ["System.Read", "System.Write"]},
            579378617: {"roleId": 579378617, "name": "DangerousRole", "system": False, "label": "DangerousRole", "privilege_ids": ["Authorization.ModifyPermissions"]},
        },
        "privileges": {
            "System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
            "System.Write": {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
            "Authorization.ModifyPermissions": {"privId": "Authorization.ModifyPermissions", "name": "Modify permission rules", "group_name": "Authorization", "on_parent": False},
        },
        "role_privileges": {
            -1: [
                {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
                {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
            ],
            579378617: [{"privId": "Authorization.ModifyPermissions", "name": "Modify permission rules", "group_name": "Authorization", "on_parent": False}],
        },
        "entity_permissions": [
            {
                "entity_type": "cluster",
                "entity_id": "domain-c1007",
                "direct": [_DIRECT_PERMISSION],
                "inherited": [_INHERITED_PERMISSION],
                "all": [_DIRECT_PERMISSION, _INHERITED_PERMISSION],
            }
        ],
    }


def _vcenter_statuses() -> list:
    return [ok("vcenter_inventory", {"cluster": 1}), ok("vcenter_authorization", {"roles": 2, "privileges": 3, "entities": 1})]


# --- AWS: build_aws_collection_evidence -----------------------------------


def test_aws_evidence_provider_and_timestamp():
    evidence = build_aws_collection_evidence(_identity(), _raw_iam(), normalize_iam(_raw_iam()), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    assert evidence["provider"] == "aws"
    assert evidence["collected_at"] is not None


def test_aws_evidence_iam_counts_match_raw_records():
    raw_iam = _raw_iam()
    evidence = build_aws_collection_evidence(_identity(), raw_iam, normalize_iam(raw_iam), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    counts = evidence["sections"]["iam_configuration"]["counts"]
    assert counts == {
        "users": len(raw_iam["UserDetailList"]),
        "groups": len(raw_iam["GroupDetailList"]),
        "roles": len(raw_iam["RoleDetailList"]),
        "policies": len(raw_iam["Policies"]),
    }


def test_aws_evidence_last_accessed_cloudtrail_and_analyzer_counts_match():
    raw_iam = _raw_iam()
    last_accessed = _last_accessed()
    cloudtrail = _cloudtrail()
    analyzer = _analyzer()
    evidence = build_aws_collection_evidence(_identity(), raw_iam, normalize_iam(raw_iam), last_accessed, cloudtrail, analyzer, _statuses())
    assert evidence["sections"]["last_accessed"]["counts"] == {"principals": len(last_accessed)}
    assert evidence["sections"]["cloudtrail"]["counts"] == {"events": len(cloudtrail["events"])}
    assert evidence["sections"]["access_analyzer"]["counts"] == {"analyzers": len(analyzer["analyzers"]), "findings": len(analyzer["findings"])}


def test_aws_evidence_normalized_counts_match_normalize_output():
    raw_iam = _raw_iam()
    normalized = normalize_iam(raw_iam)
    evidence = build_aws_collection_evidence(_identity(), raw_iam, normalized, _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    assert evidence["normalized_counts"] == {
        "users": len(normalized["users"]),
        "groups": len(normalized["groups"]),
        "roles": len(normalized["roles"]),
        "policies": len(normalized["policies"]),
        "permissions": len(normalized["permissions"]),
        "attachments": len(normalized["attachments"]),
        "memberships": len(normalized["memberships"]),
    }


def test_aws_evidence_identity_excludes_user_id_and_contains_only_safe_fields():
    evidence = build_aws_collection_evidence(_identity(), _raw_iam(), normalize_iam(_raw_iam()), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    assert set(evidence["identity"].keys()) == {"account_id", "arn", "region"}
    assert "user_id" not in evidence["identity"]


def test_aws_evidence_collection_status_preserved():
    statuses = _statuses()
    evidence = build_aws_collection_evidence(_identity(), _raw_iam(), normalize_iam(_raw_iam()), _last_accessed(), _cloudtrail(), _analyzer(), statuses)
    assert evidence["collection_status"] == [status.as_dict() for status in statuses]


def test_aws_evidence_json_contains_no_secret_shaped_strings():
    evidence = build_aws_collection_evidence(_identity(), _raw_iam(), normalize_iam(_raw_iam()), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    dumped = json.dumps(evidence, default=str).lower()
    for forbidden in ("secretaccesskey", "sessiontoken", "password", "accesskeyid", "\"pwd\""):
        assert forbidden not in dumped


def test_collected_at_survives_json_round_trip_as_iso8601(tmp_path):
    evidence = build_aws_collection_evidence(_identity(), _raw_iam(), normalize_iam(_raw_iam()), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    path = write_json(tmp_path / "collection_evidence.json", evidence)
    reloaded = json.loads(path.read_text())
    datetime.fromisoformat(reloaded["collected_at"])  # raises if not a valid ISO8601 string


# --- vCenter: build_vcenter_collection_evidence ---------------------------


def test_vcenter_evidence_provider_and_identity_is_host_only():
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    assert evidence["provider"] == "vcenter"
    assert evidence["identity"] == {"host": "https://vcenter.example.test"}


def test_vcenter_evidence_inventory_counts_match_records():
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    counts = evidence["sections"]["inventory"]["counts"]
    assert counts == {object_type: len(records) for object_type, records in inventory.items()}
    assert counts["resource_pool"] == 1
    assert counts["cluster"] == 1


def test_vcenter_evidence_authorization_counts_include_direct_and_inherited():
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    counts = evidence["sections"]["authorization"]["counts"]
    assert counts == {"roles": 2, "privileges": 3, "entities": 1, "direct_permissions": 1, "inherited_permissions": 1}


def test_vcenter_evidence_normalized_counts_match_normalize_output():
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    assert evidence["normalized_counts"]["attachments"] == len(normalized["attachments"])
    assert evidence["normalized_counts"]["policies"] == len(normalized["policies"])
    assert evidence["normalized_counts"]["roles"] == 0  # vCenter never populates common-model "roles"


def test_vcenter_evidence_collection_status_preserved():
    statuses = _vcenter_statuses()
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, statuses)
    assert evidence["collection_status"] == [status.as_dict() for status in statuses]


def test_vcenter_evidence_json_contains_no_secret_shaped_strings():
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    dumped = json.dumps(evidence, default=str).lower()
    for forbidden in ("password", "session_id", "session-id", "sessionid", "servicecontent", "sslcontext", "vmware-api-session-id"):
        assert forbidden not in dumped


# --- PDF rendering: structural ---------------------------------------------


def test_aws_evidence_pdf_is_generated_from_written_json(tmp_path):
    raw_iam = _raw_iam()
    evidence = build_aws_collection_evidence(_identity(), raw_iam, normalize_iam(raw_iam), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    json_path = write_json(tmp_path / "collection_evidence.json", evidence)
    pdf_path = render_collection_evidence_pdf(json_path, tmp_path / "aws_collection_evidence.pdf")
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_vcenter_evidence_pdf_is_generated_from_written_json(tmp_path):
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    json_path = write_json(tmp_path / "collection_evidence.json", evidence)
    pdf_path = render_collection_evidence_pdf(json_path, tmp_path / "vcenter_collection_evidence.pdf")
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_render_collection_evidence_pdf_rejects_unknown_provider(tmp_path):
    json_path = write_json(
        tmp_path / "collection_evidence.json",
        {"provider": "gcp", "collected_at": "2026-01-01T00:00:00+00:00", "identity": {}, "collection_status": [], "sections": {}, "normalized_counts": {}},
    )
    with pytest.raises(ValueError):
        render_collection_evidence_pdf(json_path, tmp_path / "out.pdf")


# --- PDF rendering: content actually corresponds to the JSON ---------------


def _captured_story(monkeypatch, json_path: Path, output_path: Path) -> list:
    """Patches SimpleDocTemplate.build to capture the exact flowables the
    renderer built (still performing a real build, so the file is also
    produced) - lets us assert the PDF's actual content without needing a
    PDF-text-extraction dependency this project doesn't otherwise need."""
    captured = {}
    original_build = evidence_report.SimpleDocTemplate.build

    def _fake_build(self, story, *args, **kwargs):
        # doc.build() drains `story` via pop(0) while flowing pages, so it
        # must be snapshotted before the real build consumes it.
        captured["story"] = list(story)
        return original_build(self, story, *args, **kwargs)

    monkeypatch.setattr(evidence_report.SimpleDocTemplate, "build", _fake_build)
    render_collection_evidence_pdf(json_path, output_path)
    return captured["story"]


def _story_text(story) -> str:
    """Recursively extracts visible text from a story (or any nested
    flowable/list within it) - handles Paragraph, Table (including a cell
    that itself holds a list of flowables), KeepTogether, and plain
    lists/tuples, so wrapping a heading and its table in KeepTogether (for
    page-break control) doesn't hide that content from this check."""
    if isinstance(story, Paragraph):
        return story.text
    if isinstance(story, Table):
        return " ".join(_story_text(cell) for row in story._cellvalues for cell in row)
    if isinstance(story, KeepTogether):
        return _story_text(story._content)
    if isinstance(story, (list, tuple)):
        return " ".join(_story_text(item) for item in story)
    return str(story) if story else ""


def test_vcenter_evidence_pdf_contains_known_fixture_records(tmp_path, monkeypatch):
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    json_path = write_json(tmp_path / "collection_evidence.json", evidence)

    story = _captured_story(monkeypatch, json_path, tmp_path / "vcenter_collection_evidence.pdf")
    text = _story_text(story)

    assert "platform-admins" in text
    assert "DangerousRole" in text
    assert "resgroup-1008" in text
    assert "Direct" in text
    assert "Inherited" in text


def test_aws_evidence_pdf_contains_known_fixture_records(tmp_path, monkeypatch):
    raw_iam = _raw_iam()
    evidence = build_aws_collection_evidence(_identity(), raw_iam, normalize_iam(raw_iam), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    json_path = write_json(tmp_path / "collection_evidence.json", evidence)

    story = _captured_story(monkeypatch, json_path, tmp_path / "aws_collection_evidence.pdf")
    text = _story_text(story)

    assert "alice" in text
    assert "POC-External-Access" in text


def test_evidence_pdfs_contain_no_em_dash(tmp_path, monkeypatch):
    raw_iam = _raw_iam()
    aws_evidence = build_aws_collection_evidence(_identity(), raw_iam, normalize_iam(raw_iam), _last_accessed(), _cloudtrail(), _analyzer(), _statuses())
    aws_json_path = write_json(tmp_path / "aws_collection_evidence.json", aws_evidence)
    aws_story = _captured_story(monkeypatch, aws_json_path, tmp_path / "aws_collection_evidence.pdf")
    assert "\u2014" not in _story_text(aws_story)

    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    vcenter_evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    vcenter_json_path = write_json(tmp_path / "vcenter_collection_evidence.json", vcenter_evidence)
    vcenter_story = _captured_story(monkeypatch, vcenter_json_path, tmp_path / "vcenter_collection_evidence.pdf")
    assert "\u2014" not in _story_text(vcenter_story)


def test_aws_access_path_diagram_matches_only_the_real_grant_and_trust_data(tmp_path):
    """The Roles & Access Paths diagram is derived, not stored in the JSON,
    so it is checked directly against the exact real fixture facts: alice's
    grant + DeveloperRole's trust agree (an edge), DeveloperRole's grant +
    AdminRole's trust agree (an edge), and alice's grant on UntrustedRole
    has no matching trust (blocked, not an edge) - this is the project's
    single most safety-critical rule (CAN_ASSUME requires both sides to
    agree), so it is verified exactly rather than just "some diagram exists"."""
    from src.evidence.evidence_report import _aws_access_paths

    raw_iam = _raw_iam()
    records = {
        "users": raw_iam["UserDetailList"],
        "groups": raw_iam["GroupDetailList"],
        "roles": raw_iam["RoleDetailList"],
        "policies": raw_iam["Policies"],
    }
    edges, blocked = _aws_access_paths(records)

    assert set(edges) == {("alice", "DeveloperRole"), ("DeveloperRole", "AdminRole")}
    assert set(blocked) == {("alice", "UntrustedRole")}


def test_evidence_pdf_never_reflects_a_password_planted_in_the_environment(tmp_path, monkeypatch):
    """The renderer's only input is collection_evidence.json - it never
    reads the environment. A real VCENTER_PASSWORD present in the process
    during a real run can therefore never leak into the evidence PDF."""
    monkeypatch.setenv("VCENTER_PASSWORD", "SUPERSECRETVALUE12345")
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    normalized = normalize_vcenter(inventory, authorization)
    evidence = build_vcenter_collection_evidence("https://vcenter.example.test", inventory, authorization, normalized, _vcenter_statuses())
    json_path = write_json(tmp_path / "collection_evidence.json", evidence)
    assert "SUPERSECRETVALUE12345" not in json_path.read_text()

    story = _captured_story(monkeypatch, json_path, tmp_path / "vcenter_collection_evidence.pdf")
    assert "SUPERSECRETVALUE12345" not in _story_text(story)


# --- vCenter pipeline integration: new artifacts + existing behavior intact


@pytest.fixture
def mocked_vcenter_pipeline():
    fake_session = Mock(rest_base_url="https://vcenter.example.test", rest_session_id="fake", soap_service_instance=Mock())
    inventory = _vcenter_inventory()
    authorization = _vcenter_authorization()
    with (
        patch.object(vcenter_pipeline.auth, "login", return_value=fake_session),
        patch.object(vcenter_pipeline.auth, "logout") as mock_logout,
        patch.object(vcenter_pipeline.inventory_collector, "collect", return_value=(inventory, ok("vcenter_inventory", {}))),
        patch.object(vcenter_pipeline.authorization_collector, "collect", return_value=(authorization, ok("vcenter_authorization", {}))),
    ):
        yield {"logout": mock_logout}


def test_vcenter_pipeline_produces_collection_evidence_artifacts(mocked_vcenter_pipeline, tmp_path):
    result = vcenter_pipeline.run_vcenter_pipeline(tmp_path)

    evidence_json_path = tmp_path / "collection_evidence.json"
    evidence_pdf_path = tmp_path / "vcenter_collection_evidence.pdf"
    assert evidence_json_path.exists()
    assert evidence_pdf_path.exists()
    assert evidence_pdf_path.read_bytes().startswith(b"%PDF")

    evidence = json.loads(evidence_json_path.read_text())
    assert evidence["provider"] == "vcenter"
    assert evidence["identity"] == {"host": "https://vcenter.example.test"}

    assert result["collection_evidence_path"] == evidence_json_path
    assert result["collection_evidence_pdf_path"] == evidence_pdf_path


def test_vcenter_pipeline_existing_findings_and_reports_unchanged(mocked_vcenter_pipeline, tmp_path):
    """Same fixture, same assertions test_vcenter_pipeline.py already makes
    about findings/report output - proves adding collection evidence changed
    nothing about existing vCenter behavior."""
    result = vcenter_pipeline.run_vcenter_pipeline(tmp_path)

    assert result["report_html_path"].exists()
    assert result["report_pdf_path"].exists()
    assert result["report_html_path"].name == "vcenter_security_audit_report.html"
    assert result["report_pdf_path"].name == "vcenter_security_audit_report.pdf"

    findings = json.loads((tmp_path / "findings" / "findings.json").read_text())
    ids = {f["id"] for f in findings}
    assert ids == {"VCENTER-ADMIN-001", "VCENTER-AUTH-001"}


# --- AWS pipeline integration: new artifacts + existing behavior intact ----


def test_aws_pipeline_produces_collection_evidence_artifacts(tmp_path, monkeypatch):
    # run_pipeline prints paths via relative_to(config.PROJECT_ROOT) - tmp_path
    # isn't under the real project root, so PROJECT_ROOT is redirected for
    # the duration of this test only (same technique tests/test_main.py uses).
    monkeypatch.setattr(main.config, "PROJECT_ROOT", tmp_path)

    raw_iam = _raw_iam()
    last_accessed_data = _last_accessed()
    last_accessed_statuses = [ok(f"last_accessed:{arn}", {"services": len(v["services_last_accessed"])}) for arn, v in last_accessed_data.items()]

    with (
        patch("src.main.iam_collector.collect", return_value=(raw_iam, ok("iam_configuration", {"users": len(raw_iam["UserDetailList"])}, 1))),
        patch("src.main.last_accessed_collector.collect", return_value=(last_accessed_data, last_accessed_statuses)),
        patch("src.main.cloudtrail_collector.collect", return_value=(_cloudtrail(), ok("cloudtrail_event_history", {"events": 1}, 1))),
        patch("src.main.access_analyzer_collector.collect", return_value=(_analyzer(), ok("access_analyzer", {"analyzers": 1, "findings": 0}))),
        patch("src.main.explain_findings", return_value=([], ok("ai_explanations", {"explanations": 0}))),
    ):
        result = main.run_pipeline(session=None, identity=_identity(), output_dir=tmp_path)

    evidence_json_path = tmp_path / "collection_evidence.json"
    evidence_pdf_path = tmp_path / "aws_collection_evidence.pdf"
    assert evidence_json_path.exists()
    assert evidence_pdf_path.exists()
    assert evidence_pdf_path.read_bytes().startswith(b"%PDF")

    evidence = json.loads(evidence_json_path.read_text())
    assert evidence["provider"] == "aws"
    assert evidence["sections"]["iam_configuration"]["counts"]["users"] == len(raw_iam["UserDetailList"])

    assert result["collection_evidence_path"] == evidence_json_path
    assert result["collection_evidence_pdf_path"] == evidence_pdf_path

    # existing artifacts still produced, unchanged in kind or location
    assert (tmp_path / "REPORT.html").exists()
    assert (tmp_path / "findings" / "findings.json").exists()
