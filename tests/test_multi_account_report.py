"""Combined multi-account HTML report tests.

No AWS calls, no orchestrator involved — renders directly from a
combined_findings.json fixture (or, for the real-aggregate case, the
actual file this session's real multi-account run already produced).
"""

import json
from pathlib import Path

import pytest

from src.report.multi_account import render_multi_account_report

_real_path = Path(__file__).parent.parent / "output" / "combined_findings.json"
REAL_COMBINED_FINDINGS = json.loads(_real_path.read_text()) if _real_path.exists() else None


def make_aggregate(**overrides):
    base = {
        "management_account_id": "957728667615",
        "organizations_status": {"succeeded": True},
        "accounts": [
            {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 7},
            {"account_label": "DEV", "account_id": "587762853586", "status": "success", "finding_count": 2},
        ],
        "accounts_succeeded": 2,
        "accounts_failed": 0,
        "findings": [
            {"account_id": "328865868092", "account_name": "PROD", "rule": "indirect_privilege_path",
             "principal": {"id": "u1", "name": "prod-alice", "type": "user"}, "policy_id": "prod-admin-policy",
             "attribution": {"attachment_type": "inline"},
             "detail": "prod-alice -> ProdDeveloperRole -> ProdAdminRole reaches administrative access "
                       "(Action=*, Resource=*) via ProdAdminPolicy."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "administrative_access",
             "principal": {"id": "r1", "name": "ProdAdminRole", "type": "role"}, "policy_id": "prod-admin-policy",
             "attribution": {"attachment_type": "inline"}, "detail": "ProdAdminRole has administrative access."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "broad_permission",
             "principal": {"id": "r1", "name": "ProdAdminRole", "type": "role"}, "policy_id": "prod-admin-policy",
             "attribution": {"attachment_type": "inline"}, "detail": "ProdAdminRole holds unrestricted access."},
            {"account_id": "587762853586", "account_name": "DEV", "rule": "administrative_access",
             "principal": {"id": "r2", "name": "dev-admin", "type": "role"}, "policy_id": "dev-admin-policy",
             "attribution": {"attachment_type": "inline"}, "detail": "dev-admin has administrative access."},
            {"account_id": "587762853586", "account_name": "DEV", "rule": "potentially_unused_access",
             "principal": {"id": "u2", "name": "dev-charlie", "type": "user"}, "policy_id": "p3",
             "attribution": {"attachment_type": "group_inherited", "source_group_name": "DevAuditors"},
             "detail": "No corresponding activity observed for dev-charlie."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "potentially_unused_access",
             "principal": {"id": "u3", "name": "prod-bob", "type": "user"}, "policy_id": "p4",
             "attribution": {"attachment_type": "group_inherited", "source_group_name": "ProdAuditors"},
             "detail": "No corresponding activity observed for prod-bob."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "broad_permission",
             "principal": {"id": "r3", "name": "OrganizationAccountAccessRole", "type": "role"}, "policy_id": "aws-managed-admin",
             "attribution": {"attachment_type": "direct_attached"}, "detail": "OrganizationAccountAccessRole holds unrestricted access."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "administrative_access",
             "principal": {"id": "r3", "name": "OrganizationAccountAccessRole", "type": "role"}, "policy_id": "aws-managed-admin",
             "attribution": {"attachment_type": "direct_attached"}, "detail": "OrganizationAccountAccessRole has administrative access."},
            {"account_id": "328865868092", "account_name": "PROD", "rule": "potentially_unused_access",
             "principal": {"id": "r4", "name": "AWSServiceRoleForSupport", "type": "role"}, "policy_id": "p5",
             "attribution": {"attachment_type": "direct_attached"}, "detail": "No corresponding activity observed for AWSServiceRoleForSupport."},
        ],
        "total_findings": 9,
    }
    base.update(overrides)
    return base


def write_aggregate(tmp_path, aggregate):
    path = tmp_path / "combined_findings.json"
    path.write_text(json.dumps(aggregate))
    return path


def render(tmp_path, aggregate):
    path = write_aggregate(tmp_path, aggregate)
    return render_multi_account_report(path, tmp_path / "MULTI_ACCOUNT_REPORT.html")


def test_title_exists(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "<title>" in content
    assert "Sentinel" in content
    assert "Multi-Account" in content


def test_management_account_appears(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "957728667615" in content


def test_prod_and_dev_appear(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "PROD" in content
    assert "DEV" in content


def test_both_account_ids_appear(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "328865868092" in content
    assert "587762853586" in content


def test_account_counts_are_correct(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert ">2<" in content  # accounts_succeeded
    assert ">0<" in content  # accounts_failed


def test_total_findings_appears(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert ">9<" in content  # total_findings stat


def test_key_risk_content_appears(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "Key Security Risks" in content
    # the escalation chain should be rendered vertically
    assert "prod-alice" in content
    assert "ProdDeveloperRole" in content
    assert "ProdAdminRole" in content
    assert "Administrative Access" in content
    # high-risk / review labeling derived from existing rule names
    assert "HIGH RISK" in content


def test_drilldown_links_exist(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert 'href="PROD/REPORT.html"' in content
    assert 'href="DEV/REPORT.html"' in content


def test_all_findings_remain_represented_in_collapsed_sections(tmp_path):
    aggregate = make_aggregate()
    content = render(tmp_path, aggregate).read_text()
    assert "<details" in content
    for finding in aggregate["findings"]:
        assert finding["principal"]["name"] in content
        assert finding["policy_id"] in content


def test_account_name_and_id_association_preserved(tmp_path):
    aggregate = make_aggregate()
    content = render(tmp_path, aggregate).read_text()
    for finding in aggregate["findings"]:
        assert finding["account_name"] in content
        assert finding["account_id"] in content


def test_empty_findings_handled(tmp_path):
    aggregate = make_aggregate(findings=[], total_findings=0)
    output = render(tmp_path, aggregate)
    content = output.read_text()
    assert "No findings" in content
    assert output.exists()


def test_failed_account_renders_without_crashing(tmp_path):
    aggregate = make_aggregate(
        accounts=[
            {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 7},
            {"account_label": "DEV", "account_id": "587762853586", "status": "failed",
             "failure_stage": "authentication", "error": "Could not assume role: AccessDenied"},
        ],
        accounts_succeeded=1,
        accounts_failed=1,
        findings=[f for f in make_aggregate()["findings"] if f["account_name"] == "PROD"],
        total_findings=7,
    )
    output = render(tmp_path, aggregate)
    content = output.read_text()
    assert "PROD" in content
    assert "DEV" in content
    assert "Failed" in content
    assert output.exists()


def _key_risks_section(content: str) -> str:
    start = content.index("Key Security Risks")
    end = content.index("Account Drill-Down")
    return content[start:end]


def test_key_risks_show_only_intentional_poc_scenarios(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    section = _key_risks_section(content)

    for expected in ("prod-alice", "ProdAdminRole", "prod-bob", "dev-admin", "dev-charlie"):
        assert expected in section, f"{expected} missing from Key Security Risks"


def test_key_risks_exclude_aws_native_noise(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    section = _key_risks_section(content)

    assert "OrganizationAccountAccessRole" not in section
    assert "AWSServiceRoleForSupport" not in section
    # but the noise must still be present somewhere in the full report (All Findings)
    assert "OrganizationAccountAccessRole" in content
    assert "AWSServiceRoleForSupport" in content


def test_all_findings_sections_collapsed_by_default(tmp_path):
    content = render(tmp_path, make_aggregate()).read_text()
    assert "<details" in content
    assert "<details open" not in content


def test_existing_report_output_not_affected(tmp_path):
    """render_multi_account_report must only ever write its own output file."""
    path = write_aggregate(tmp_path, make_aggregate())
    before = set(tmp_path.iterdir())

    render_multi_account_report(path, tmp_path / "MULTI_ACCOUNT_REPORT.html")

    after = set(tmp_path.iterdir())
    new_files = after - before
    assert new_files == {tmp_path / "MULTI_ACCOUNT_REPORT.html"}


@pytest.mark.skipif(REAL_COMBINED_FINDINGS is None, reason="output/combined_findings.json not present from a real run")
def test_all_findings_appear_for_the_current_real_aggregate(tmp_path):
    path = tmp_path / "combined_findings.json"
    path.write_text(json.dumps(REAL_COMBINED_FINDINGS))
    output = render_multi_account_report(path, tmp_path / "MULTI_ACCOUNT_REPORT.html")
    content = output.read_text()

    assert REAL_COMBINED_FINDINGS["total_findings"] == len(REAL_COMBINED_FINDINGS["findings"])
    assert "328865868092" in content
    assert "587762853586" in content
    for finding in REAL_COMBINED_FINDINGS["findings"]:
        assert finding["account_name"] in content
        assert finding["account_id"] in content
