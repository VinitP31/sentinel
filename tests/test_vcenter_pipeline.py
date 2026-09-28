"""vCenter pipeline integration tests.

auth/collectors are mocked (no real vCenter call); normalize, vCenter
findings, evidence, and report all run for real against the mocked
collector output, proving the actual integration works end to end.
"""

import json
from unittest.mock import Mock, patch

import pytest

from src.util.status import ok
from src.vcenter import pipeline

FAKE_INVENTORY = {
    "datacenter": [{"id": "datacenter-2001", "type": "datacenter", "name": "DC-Lab", "parent": None}],
    "folder": [
        {"id": "group-d1", "type": "folder", "name": "Datacenters", "parent": None},
        {"id": "group-v2006", "type": "folder", "name": "AppTeam", "parent": None},
    ],
    "cluster": [],
    "host": [],
    "vm": [],
}

FAKE_AUTHORIZATION = {
    "roles": {
        1148447843: {"roleId": 1148447843, "name": "ReadOnlyPlus", "system": False, "label": "ReadOnlyPlus", "privilege_ids": ["System.View"]},
        -1: {"roleId": -1, "name": "Admin", "system": True, "label": "Admin", "privilege_ids": ["System.Read", "System.Write", "Folder.Create"]},
        579378617: {"roleId": 579378617, "name": "ConnectorReaderPlus", "system": False, "label": "ConnectorReaderPlus", "privilege_ids": ["System.View", "Authorization.ModifyPermissions"]},
    },
    "privileges": {
        "System.View": {"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False},
        "System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
        "System.Write": {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
        "Folder.Create": {"privId": "Folder.Create", "name": "Create Folder", "group_name": "Folder", "on_parent": False},
        "Authorization.ModifyPermissions": {"privId": "Authorization.ModifyPermissions", "name": "Modify permission rules", "group_name": "Authorization", "on_parent": False},
    },
    "role_privileges": {
        1148447843: [{"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False}],
        -1: [
            {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
            {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
            {"privId": "Folder.Create", "name": "Create Folder", "group_name": "Folder", "on_parent": False},
        ],
        579378617: [
            {"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False},
            {"privId": "Authorization.ModifyPermissions", "name": "Modify permission rules", "group_name": "Authorization", "on_parent": False},
        ],
    },
    "entity_permissions": [
        {
            "entity_type": "folder",
            "entity_id": "group-v2006",
            "direct": [
                {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                {"principal": "VSPHERE.LOCAL\\svc-conn-min", "group": False, "roleId": 579378617, "role_name": "ConnectorReaderPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
            ],
            "inherited": [],
            "all": [
                {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                {"principal": "VSPHERE.LOCAL\\svc-conn-min", "group": False, "roleId": 579378617, "role_name": "ConnectorReaderPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
            ],
        },
    ],
}


@pytest.fixture
def mocked_pipeline():
    """Patches auth/collectors only - real normalize/vCenter findings/
    evidence/report run underneath."""
    fake_session = Mock(rest_base_url="https://vcenter.example.test", rest_session_id="fake", soap_service_instance=Mock())

    with (
        patch.object(pipeline.auth, "login", return_value=fake_session) as mock_login,
        patch.object(pipeline.auth, "logout") as mock_logout,
        patch.object(pipeline.inventory_collector, "collect", return_value=(FAKE_INVENTORY, ok("vcenter_inventory", {}))) as mock_inventory,
        patch.object(pipeline.authorization_collector, "collect", return_value=(FAKE_AUTHORIZATION, ok("vcenter_authorization", {}))) as mock_authorization,
    ):
        yield {
            "login": mock_login,
            "logout": mock_logout,
            "inventory": mock_inventory,
            "authorization": mock_authorization,
        }


def test_pipeline_calls_vcenter_collectors(mocked_pipeline, tmp_path):
    pipeline.run_vcenter_pipeline(tmp_path)

    mocked_pipeline["login"].assert_called_once()
    mocked_pipeline["inventory"].assert_called_once()
    mocked_pipeline["authorization"].assert_called_once()
    mocked_pipeline["logout"].assert_called_once()


def test_pipeline_produces_normalized_common_model(mocked_pipeline, tmp_path):
    result = pipeline.run_vcenter_pipeline(tmp_path)

    assert result["complete"] is True
    assert (tmp_path / "normalized" / "vcenter.json").exists()


def test_pipeline_does_not_generate_a_full_graph(mocked_pipeline, tmp_path):
    pipeline.run_vcenter_pipeline(tmp_path)
    assert not (tmp_path / "graph").exists()


def test_pipeline_produces_vcenter_findings_grouped_by_rule(mocked_pipeline, tmp_path):
    result = pipeline.run_vcenter_pipeline(tmp_path)

    assert result["finding_count"] == 2  # one Administrative Access finding, one Authorization Management Access finding
    findings = json.loads((tmp_path / "findings" / "findings.json").read_text())
    ids = {f["id"] for f in findings}
    assert ids == {"VCENTER-ADMIN-001", "VCENTER-AUTH-001"}
    admin_finding = next(f for f in findings if f["id"] == "VCENTER-ADMIN-001")
    assert len(admin_finding["principals"]) == 1  # Administrators group


def test_pipeline_generates_html_and_pdf_reports(mocked_pipeline, tmp_path):
    result = pipeline.run_vcenter_pipeline(tmp_path)

    assert result["report_html_path"].exists()
    assert result["report_pdf_path"].exists()
    assert result["report_html_path"].name == "vcenter_security_audit_report.html"
    assert result["report_pdf_path"].name == "vcenter_security_audit_report.pdf"


def test_pipeline_never_calls_potentially_unused_access(mocked_pipeline, tmp_path):
    from src.analysis import rules

    with patch.object(rules, "potentially_unused_access") as mock_unused:
        pipeline.run_vcenter_pipeline(tmp_path)
        mock_unused.assert_not_called()


def test_pipeline_evidence_has_no_fabricated_activity(mocked_pipeline, tmp_path):
    pipeline.run_vcenter_pipeline(tmp_path)

    evidence = json.loads((tmp_path / "evidence" / "evidence_package.json").read_text())
    for package in evidence["packages"].values():
        assert package["observed_activity"]["events"] == []
        assert package["last_accessed"] == []


def test_pipeline_admin_role_keeps_real_privileges(mocked_pipeline, tmp_path):
    pipeline.run_vcenter_pipeline(tmp_path)

    findings = json.loads((tmp_path / "findings" / "findings.json").read_text())
    admin_finding = next(f for f in findings if f["id"] == "VCENTER-ADMIN-001")
    entry = admin_finding["principals"][0]
    assert "*" not in entry["privileges"]
    assert entry["privileges"] == ["System.Read", "System.Write", "Folder.Create"]


def test_pipeline_collection_failure_reported_cleanly(tmp_path):
    fake_session = Mock(rest_base_url="https://vcenter.example.test", rest_session_id="fake", soap_service_instance=Mock())
    from src.util.status import failed

    with (
        patch.object(pipeline.auth, "login", return_value=fake_session),
        patch.object(pipeline.auth, "logout") as mock_logout,
        patch.object(pipeline.inventory_collector, "collect", return_value=({}, failed("vcenter_inventory", "boom"))),
    ):
        result = pipeline.run_vcenter_pipeline(tmp_path)

    assert result["complete"] is False
    mock_logout.assert_called_once()
