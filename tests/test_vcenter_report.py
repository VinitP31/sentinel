"""vCenter report generation tests. Small fixtures only, no real vCenter
pipeline output needed, no network call."""

import json

import pytest

from src.vcenter.report import TITLE, build_summary, render_vcenter_pdf, render_vcenter_report


def make_pipeline_output(tmp_path, findings=None):
    (tmp_path / "raw").mkdir()
    (tmp_path / "normalized").mkdir()
    (tmp_path / "findings").mkdir()
    (tmp_path / "evidence").mkdir()

    (tmp_path / "raw" / "inventory.json").write_text(json.dumps({
        "datacenter": [{"id": "dc-1", "type": "datacenter", "name": "DC1", "parent": None}],
        "folder": [{"id": "f-1", "type": "folder", "name": "AppTeam", "parent": None}],
        "cluster": [],
        "host": [],
        "vm": [],
    }))
    (tmp_path / "raw" / "authorization.json").write_text(json.dumps({
        "roles": {-1: {"roleId": -1, "name": "Admin", "system": True, "label": "Admin", "privilege_ids": ["System.Read"]}},
        "privileges": {"System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False}},
        "role_privileges": {-1: [{"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False}]},
        "entity_permissions": [
            {
                "entity_type": "folder", "entity_id": "f-1",
                "direct": [{"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "f-1"}],
                "inherited": [],
                "all": [{"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "f-1"}],
            }
        ],
    }))
    (tmp_path / "normalized" / "vcenter.json").write_text(json.dumps({
        "users": [],
        "groups": [{"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\Administrators", "name": "VSPHERE.LOCAL\\Administrators", "arn": None, "created_at": None}],
        "roles": [],
        "policies": [{"provider": "vcenter", "type": "policy", "id": "-1@f-1", "name": "Admin", "arn": None, "policy_type": "system", "document": None}],
        "permissions": [{"policy_id": "-1@f-1", "effect": "Allow", "actions": ["System.Read"], "resources": ["f-1"]}],
        "attachments": [{"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@f-1", "attachment_type": "vcenter_direct", "entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True}],
        "memberships": [],
    }))

    if findings is None:
        findings = [
            {
                "id": "VCENTER-ADMIN-001",
                "rule": "vcenter_administrative_access",
                "title": "Administrative Access",
                "severity": "high",
                "role_name": "Admin",
                "total_privilege_count": 1,
                "notable_privileges": ["System.Read"],
                "principals": [
                    {
                        "principal": {"id": "VSPHERE.LOCAL\\Administrators", "name": "VSPHERE.LOCAL\\Administrators", "type": "group"},
                        "role": {"id": "-1", "name": "Admin", "system": True},
                        "privileges": ["System.Read"],
                        "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                        "assignments_summary": "AppTeam (direct)",
                    }
                ],
                "detail": "1 principal holds the built-in Admin role, granting unrestricted administrative control over vCenter.",
            }
        ]
    (tmp_path / "findings" / "findings.json").write_text(json.dumps(findings))
    (tmp_path / "findings" / "collection_report.json").write_text(json.dumps({
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "provider": "vcenter",
        "complete": True,
        "sources": [],
    }))
    (tmp_path / "evidence" / "evidence_package.json").write_text(json.dumps({"packages": {}}))

    return tmp_path


def test_summary_counts_come_from_actual_data(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    from src.vcenter.report import load_pipeline_output

    data = load_pipeline_output(output_dir)
    summary = build_summary(data)

    assert summary["inventory_object_count"] == 2
    assert summary["roles"] == 1
    assert summary["direct_permissions"] == 1
    assert summary["inherited_permissions"] == 0
    assert summary["findings"] == 1
    assert summary["findings_by_severity"] == {"high": 1}
    assert summary["affected_principal_count"] == 1
    assert summary["affected_principals"] == ["VSPHERE.LOCAL\\Administrators"]


def test_executive_summary_does_not_expose_normalization_counts(tmp_path):
    """policies/permissions/attachments/memberships are implementation
    detail, not executive-summary material."""
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    summary_section = content[content.index('id="summary"'):content.index('id="findings"')]
    assert "attachments" not in summary_section.lower()
    assert "memberships" not in summary_section.lower()


def test_html_report_has_vcenter_title_no_aws_leakage(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)

    content = html_path.read_text()
    assert f"<title>{TITLE}</title>" in content
    assert "AWS IAM Security Audit Report" not in content
    assert "CloudTrail" not in content
    assert "Access Analyzer" not in content
    assert "single AWS account" not in content


def test_html_report_shows_concrete_finding_not_vague_text(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()

    assert "No findings were detected" not in content
    assert "VCENTER-ADMIN-001" in content
    assert "VSPHERE.LOCAL\\Administrators" in content
    assert "What Was Detected" in content
    assert "Why This Matters" in content
    assert "Recommendation" in content


def test_html_report_does_not_dump_full_privilege_list(tmp_path):
    """The Admin role's total_privilege_count can be large - the finding
    body must show only notable_privileges plus the count, not every
    privilege the role actually has."""
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin",
            "total_privilege_count": 464,
            "notable_privileges": ["Authorization.ModifyPermissions", "Global.Settings"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\Administrator", "name": "VSPHERE.LOCAL\\Administrator", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": [f"Priv{i}" for i in range(464)],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()

    assert "464" in content
    assert "Priv0" not in content  # raw full list never dumped
    assert "Authorization.ModifyPermissions" in content


def test_html_report_zero_findings_case_shows_summary_not_manufactured_findings(tmp_path):
    output_dir = make_pipeline_output(tmp_path, findings=[])
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()

    assert "No security findings were produced" in content
    assert 'class="finding' not in content  # no finding card rendered - nothing manufactured


def test_html_report_groups_multiple_principals_into_one_finding_card(tmp_path):
    """7 Admin holders must appear as ONE Administrative Access card with a
    7-row Affected Principals table, not seven separate finding cards."""
    principals = [
        {
            "principal": {"id": f"VSPHERE.LOCAL\\user{i}", "name": f"VSPHERE.LOCAL\\user{i}", "type": "user"},
            "role": {"id": "-1", "name": "Admin", "system": True},
            "privileges": ["System.Read"],
            "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
            "assignments_summary": "AppTeam (direct)",
        }
        for i in range(7)
    ]
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": principals,
            "detail": "7 principals hold the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()

    assert content.count('class="finding ') + content.count('class="finding"') <= 2  # one finding div wrapper (plus maybe class="finding-header" etc, not 7 cards)
    for i in range(7):
        assert f"user{i}" in content


def test_html_report_entity_names_are_correct_not_collapsed(tmp_path):
    """Different entities in the same finding must show their own real
    names, never all mislabeled as the same entity."""
    principals = [
        {
            "principal": {"id": "VSPHERE.LOCAL\\alice", "name": "VSPHERE.LOCAL\\alice", "type": "user"},
            "role": {"id": "-1", "name": "Admin", "system": True},
            "privileges": ["System.Read"],
            "assignments": [
                {"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"},
                {"entity_id": "f-2", "entity_type": "folder", "entity_name": "InfraTeam", "propagate": True, "attachment_type": "vcenter_inherited"},
            ],
            "assignments_summary": "AppTeam (direct), 1 additional entity via inheritance",
        }
    ]
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": principals,
            "detail": "1 principal holds the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "InfraTeam" in content
    assert "AppTeam" in content


def test_relationship_views_deduplicate_identical_patterns(tmp_path):
    principals = [
        {
            "principal": {"id": f"VSPHERE.LOCAL\\user{i}", "name": f"VSPHERE.LOCAL\\user{i}", "type": "user"},
            "role": {"id": "-1", "name": "Admin", "system": True},
            "privileges": ["System.Read"],
            "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
            "assignments_summary": "AppTeam (direct)",
        }
        for i in range(6)
    ]
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": principals,
            "detail": "6 principals hold the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    relationships_section = content[content.index('id="relationships"'):]
    assert relationships_section.count('class="view"') == 1  # one diagram, not six


def test_recommendation_distinguishes_modify_permissions_from_modify_roles(tmp_path):
    findings = [
        {
            "id": "VCENTER-AUTH-001", "rule": "vcenter_authorization_management_access", "title": "Authorization Management Access",
            "severity": "medium",
            "sensitive_privileges": ["Authorization.ModifyPermissions"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\svc-conn-min", "name": "VSPHERE.LOCAL\\svc-conn-min", "type": "user"},
                    "role": {"id": "579378617", "name": "ConnectorReaderPlus", "system": False},
                    "privileges": ["Authorization.ModifyPermissions"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds a role containing Authorization.ModifyPermissions.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "Authorization.ModifyPermissions" in content
    assert "Authorization.ModifyRoles" not in content  # must not describe the wrong privilege


def test_recommendation_asks_to_verify_service_account_before_removal(tmp_path):
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\vpxd-extension-abc", "name": "VSPHERE.LOCAL\\vpxd-extension-abc", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "verify" in content.lower()
    assert "service account" in content.lower()


def test_pdf_report_generated_with_findings(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    pdf_path = render_vcenter_pdf(output_dir)

    assert pdf_path.exists()
    assert pdf_path.suffix == ".pdf"
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_pdf_report_generated_zero_findings(tmp_path):
    output_dir = make_pipeline_output(tmp_path, findings=[])
    pdf_path = render_vcenter_pdf(output_dir)
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_html_and_pdf_written_to_same_output_dir(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    pdf_path = render_vcenter_pdf(output_dir)

    assert html_path.parent == output_dir
    assert pdf_path.parent == output_dir
    assert html_path.name == "vcenter_security_audit_report.html"
    assert pdf_path.name == "vcenter_security_audit_report.pdf"


def test_missing_pipeline_output_raises_instead_of_reconnecting(tmp_path):
    with pytest.raises(FileNotFoundError):
        render_vcenter_report(tmp_path)


def test_html_report_has_human_readable_date_not_raw_iso(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "2026-01-01T00:05:00" not in content
    assert "January 01, 2026" in content


def test_html_report_has_metric_cards_distinguishing_findings_from_severity(tmp_path):
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 464, "notable_privileges": ["Authorization.ModifyPermissions"],
            "principals": [
                {
                    "principal": {"id": f"VSPHERE.LOCAL\\user{i}", "name": f"VSPHERE.LOCAL\\user{i}", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
                for i in range(7)
            ],
            "detail": "7 principals hold the built-in Admin role.",
        },
        {
            "id": "VCENTER-AUTH-001", "rule": "vcenter_authorization_management_access", "title": "Authorization Management Access",
            "severity": "medium", "sensitive_privileges": ["Authorization.ModifyPermissions"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\svc-conn-min", "name": "VSPHERE.LOCAL\\svc-conn-min", "type": "user"},
                    "role": {"id": "579378617", "name": "ConnectorReaderPlus", "system": False},
                    "privileges": ["Authorization.ModifyPermissions"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds a role containing Authorization.ModifyPermissions.",
        },
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()

    assert "table metrics" in content or 'class="metrics"' in content
    assert "Total Findings" in content
    assert "Affected Principals" in content
    assert "High Risk" in content
    assert "Review" in content
    assert '<td>2</td>' in content  # total findings = 2 finding cards/types, never the 8 principal instances
    assert '<td>8</td>' in content  # affected principals = 8 unique principals
    assert '<td class="risk">7</td>' in content  # 7 high-risk instances
    assert '<td class="review">1</td>' in content  # 1 review instance


def test_principals_table_has_no_category_column(tmp_path):
    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "<th>Category</th>" not in content
    assert "<th>Principal</th><th>Type</th><th>Role</th><th>Scope</th><th>Access</th>" in content


def test_recommendation_separates_named_and_service_accounts_not_one_paragraph(tmp_path):
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\Administrator", "name": "VSPHERE.LOCAL\\Administrator", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                },
                {
                    "principal": {"id": "VSPHERE.LOCAL\\vpxd-abc", "name": "VSPHERE.LOCAL\\vpxd-abc", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                },
            ],
            "detail": "2 principals hold the built-in Admin role.",
        }
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "Named principals" in content
    assert "Service accounts" in content
    assert content.count("recommendation-item") >= 2  # two separate items, not one paragraph


def test_relationship_views_exactly_one_per_finding_type(tmp_path):
    """Target: two diagrams total for the real report (one per finding
    type), never one per principal or per role/scope sub-pattern."""
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\Administrator", "name": "VSPHERE.LOCAL\\Administrator", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                },
                {
                    "principal": {"id": "VSPHERE.LOCAL\\dev-alice", "name": "VSPHERE.LOCAL\\dev-alice", "type": "user"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-2", "entity_type": "datacenter", "entity_name": "DC-Lab", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "DC-Lab (direct)",
                },
            ],
            "detail": "2 principals hold the built-in Admin role.",
        },
        {
            "id": "VCENTER-AUTH-001", "rule": "vcenter_authorization_management_access", "title": "Authorization Management Access",
            "severity": "medium", "sensitive_privileges": ["Authorization.ModifyPermissions"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\svc-conn-min", "name": "VSPHERE.LOCAL\\svc-conn-min", "type": "user"},
                    "role": {"id": "579378617", "name": "ConnectorReaderPlus", "system": False},
                    "privileges": ["Authorization.ModifyPermissions"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds a role containing Authorization.ModifyPermissions.",
        },
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    relationships_section = content[content.index('id="relationships"'):]
    assert relationships_section.count('class="view"') == 2


def test_no_uppercase_text_transform_on_subsection_headings(tmp_path):
    import re

    output_dir = make_pipeline_output(tmp_path)
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    h3_rule = re.search(r"h3\s*\{[^}]*\}", content)
    assert h3_rule is not None
    assert "text-transform" not in h3_rule.group(0)
    assert "font-weight: 700" in h3_rule.group(0)


# --- VCENTER-NOACCESS-001 / VCENTER-PRIV-001: report rendering --------------


def _no_access_finding():
    return {
        "id": "VCENTER-NOACCESS-001", "rule": "vcenter_no_access_override", "title": "No Access Override",
        "severity": "medium",
        "principals": [
            {
                "principal": {"id": "VSPHERE.LOCAL\\ReadOnlyUsers", "name": "VSPHERE.LOCAL\\ReadOnlyUsers", "type": "group"},
                "role": {"id": "-5", "name": "NoAccess", "system": True},
                "privileges": [],
                "assignments": [{"entity_id": "f-2", "entity_type": "folder", "entity_name": "Sensitive", "propagate": True, "attachment_type": "vcenter_direct"}],
                "assignments_summary": "Sensitive (direct)",
            }
        ],
        "detail": (
            "1 authorization subject holds an explicit No Access assignment, which overrides any "
            "otherwise-applicable access for that principal at the entity where it is assigned. This "
            "is reported as an explicit access restriction to verify, not asserted as a vulnerability."
        ),
    }


def _high_impact_finding():
    return {
        "id": "VCENTER-PRIV-001", "rule": "vcenter_high_impact_privilege_access", "title": "High-Impact Privilege Access",
        "severity": "high",
        "high_impact_privileges": ["Global.Settings", "Host.Config.Settings", "Sessions.TerminateSession"],
        "principals": [
            {
                "principal": {"id": "VSPHERE.LOCAL\\platform-admins", "name": "VSPHERE.LOCAL\\platform-admins", "type": "group"},
                "role": {"id": "-405023589", "name": "DangerousRole", "system": False},
                "privileges": ["Global.Settings", "Host.Config.Settings", "Sessions.TerminateSession"],
                "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                "assignments_summary": "AppTeam (direct)",
            }
        ],
        "detail": (
            "1 principal holds a role containing one or more high-impact privileges (Global.Settings, "
            "Host.Config.Settings, Sessions.TerminateSession), each capable of terminating other "
            "sessions or modifying vCenter-wide or host configuration."
        ),
    }


def test_no_access_finding_renders_as_review_not_high_risk(tmp_path):
    output_dir = make_pipeline_output(tmp_path, findings=[_no_access_finding()])
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "No Access Override" in content
    assert "severity-medium" in content
    assert ">REVIEW<" in content


def test_no_access_wording_never_asserts_a_vulnerability(tmp_path):
    output_dir = make_pipeline_output(tmp_path, findings=[_no_access_finding()])
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "not asserted as a vulnerability" in content
    assert "This is a restriction, not a grant" in content


def test_no_access_recommendation_asks_to_verify_never_to_remove():
    from src.vcenter.report import _no_access_recommendation

    items = _no_access_recommendation(_no_access_finding())
    assert len(items) == 1
    label, text = items[0]
    assert label == "Group"
    assert "confirm this restriction is intentional" in text.lower()
    assert "remove" not in text.lower()
    assert "replace" not in text.lower()


def test_no_access_evidence_text_says_zero_privileges():
    from src.vcenter.report import _evidence_text

    assert _evidence_text(_no_access_finding()) == (
        "No privileges are granted by this role - it is an explicit deny of any "
        "otherwise-applicable access at the entity where it is assigned."
    )


def test_high_impact_finding_renders_as_high_risk(tmp_path):
    output_dir = make_pipeline_output(tmp_path, findings=[_high_impact_finding()])
    html_path = render_vcenter_report(output_dir)
    content = html_path.read_text()
    assert "High-Impact Privilege Access" in content
    assert "severity-high" in content
    assert ">HIGH RISK<" in content


def test_high_impact_why_it_matters_names_every_detected_privilege():
    from src.vcenter.report import _priv_why_it_matters

    text = _priv_why_it_matters(_high_impact_finding())
    assert "Sessions.TerminateSession" in text
    assert "terminate other users' active sessions" in text
    assert "Global.Settings" in text
    assert "Host.Config.Settings" in text


def test_high_impact_recommendation_classifies_group_correctly_not_as_named():
    """The real subject for this finding is a group (platform-admins) - must
    use the Group bucket, never the two-way named/service split that
    misclassified a group as "Named principals" for VCENTER-ADMIN-001
    before that was fixed."""
    from src.vcenter.report import _priv_recommendation

    items = _priv_recommendation(_high_impact_finding())
    labels = {label for label, _ in items}
    assert "Group" in labels
    assert "Named principals" not in labels


def test_high_impact_evidence_lists_detected_privileges():
    from src.vcenter.report import _evidence_text

    assert _evidence_text(_high_impact_finding()) == "Privilege(s) granted: Global.Settings, Host.Config.Settings, Sessions.TerminateSession."


def test_report_with_all_four_finding_types_generates_cleanly(tmp_path):
    """All four vCenter finding types together must still render one clean
    report - the fallback 'no findings' text and per-id dispatch must both
    handle the full set, not just the original two."""
    findings = [
        {
            "id": "VCENTER-ADMIN-001", "rule": "vcenter_administrative_access", "title": "Administrative Access",
            "severity": "high", "role_name": "Admin", "total_privilege_count": 1, "notable_privileges": ["System.Read"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\Administrators", "name": "VSPHERE.LOCAL\\Administrators", "type": "group"},
                    "role": {"id": "-1", "name": "Admin", "system": True},
                    "privileges": ["System.Read"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 authorization subject holds the built-in Admin role.",
        },
        {
            "id": "VCENTER-AUTH-001", "rule": "vcenter_authorization_management_access", "title": "Authorization Management Access",
            "severity": "medium", "sensitive_privileges": ["Authorization.ModifyPermissions"],
            "principals": [
                {
                    "principal": {"id": "VSPHERE.LOCAL\\svc-conn-min", "name": "VSPHERE.LOCAL\\svc-conn-min", "type": "user"},
                    "role": {"id": "579378617", "name": "ConnectorReaderPlus", "system": False},
                    "privileges": ["Authorization.ModifyPermissions"],
                    "assignments": [{"entity_id": "f-1", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True, "attachment_type": "vcenter_direct"}],
                    "assignments_summary": "AppTeam (direct)",
                }
            ],
            "detail": "1 principal holds a role containing Authorization.ModifyPermissions.",
        },
        _no_access_finding(),
        _high_impact_finding(),
    ]
    output_dir = make_pipeline_output(tmp_path, findings=findings)
    html_path = render_vcenter_report(output_dir)
    pdf_path = render_vcenter_pdf(output_dir)
    content = html_path.read_text()
    for finding_id in ("VCENTER-ADMIN-001", "VCENTER-AUTH-001", "VCENTER-NOACCESS-001", "VCENTER-PRIV-001"):
        assert finding_id in content
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")
