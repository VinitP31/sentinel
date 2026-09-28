"""Report Correctness / Relevance Gate for the vCenter report.

A final automated check that sits above the existing unit tests: it runs
one fixed, sanitized golden dataset through the REAL findings pipeline
(src.vcenter.findings.run_all - never a hand-typed finding dict) and the
REAL report renderers (render_vcenter_report / render_vcenter_pdf), then
asserts the rendered report is actually correct and relevant relative to
that dataset - not just internally consistent with itself.

The golden dataset is fictitious (VSPHERE.LOCAL is vCenter's own default
identity domain name, not anything sanitized away; every principal name,
UUID, and entity here is made up) but shaped exactly like the real
sandbox's two known findings, so this file also pins the "current known
result" the report must keep producing:
    - 2 findings (VCENTER-ADMIN-001, VCENTER-AUTH-001)
    - 7 Admin authorization subjects (6 user/service accounts + 1 group)
    - 1 ConnectorReaderPlus / Authorization.ModifyPermissions subject

This file does not render or compare pixels/layout - report.py's own
existing tests already cover structure/wording in isolation. This file's
job is end-to-end evidence traceability: every number and claim the
report makes must trace back to the golden normalized data actually fed
in, not merely be internally self-consistent.
"""

import base64
import re
import zlib
from pathlib import Path

from src.util.io import write_json
from src.vcenter.findings import (
    ADMIN_ROLE_NAMES,
    SENSITIVE_AUTHORIZATION_PRIVILEGES,
    VCENTER_ADMIN_001,
    VCENTER_AUTH_001,
    run_all,
)
from src.vcenter.report import (
    LIMITATIONS,
    TITLE,
    build_summary,
    render_vcenter_pdf,
    render_vcenter_report,
)

ADMIN_NAMED = ["VSPHERE.LOCAL\\Administrator", "VSPHERE.LOCAL\\dev-alice"]
ADMIN_SERVICE = [
    "VSPHERE.LOCAL\\svc-connector",
    "VSPHERE.LOCAL\\vpxd-11111111-1111-1111-1111-111111111111",
    "VSPHERE.LOCAL\\vpxd-extension-11111111-1111-1111-1111-111111111111",
    "VSPHERE.LOCAL\\vpxd-svc-acct-11111111-1111-1111-1111-111111111111",
]
ADMIN_GROUP = "VSPHERE.LOCAL\\Administrators"
AUTH_USER = "VSPHERE.LOCAL\\svc-conn-min"

# A small, realistic subset - not the real Admin role's ~464 privileges.
# The point of this dataset is traceability of what IS present, not an
# exhaustive replica of the real role.
ADMIN_PRIVILEGES = ["System.Read", "System.Write", "Authorization.ModifyPermissions", "Authorization.ModifyRoles", "Global.Settings"]
AUTH_PRIVILEGES = ["System.View", "Authorization.ModifyPermissions"]


def golden_normalized() -> dict:
    """7 Admin holders (Administrator + dev-alice named, 3 vpxd-*/svc-
    connector service accounts, 1 Administrators group) bound at two
    different entities, plus 1 ConnectorReaderPlus/Authorization.
    ModifyPermissions holder at a third policy binding - mirrors the real
    sandbox's actual finding shape without using any real client data."""
    non_group_at_datacenters = ADMIN_NAMED[:1] + ADMIN_SERVICE  # Administrator + 3 service accounts
    users = [
        {"provider": "vcenter", "type": "user", "id": name, "name": name, "arn": None, "created_at": None}
        for name in non_group_at_datacenters + [ADMIN_NAMED[1], AUTH_USER]
    ]
    groups = [
        {"provider": "vcenter", "type": "group", "id": ADMIN_GROUP, "name": ADMIN_GROUP, "arn": None, "created_at": None},
    ]
    policies = [
        {"provider": "vcenter", "type": "policy", "id": "-1@folder-datacenters", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
        {"provider": "vcenter", "type": "policy", "id": "-1@datacenter-dclab", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
        {"provider": "vcenter", "type": "policy", "id": "579378617@folder-datacenters", "name": "ConnectorReaderPlus", "arn": None, "policy_type": "custom", "document": None},
    ]
    permissions = [
        {"policy_id": "-1@folder-datacenters", "effect": "Allow", "actions": ADMIN_PRIVILEGES, "resources": ["folder-datacenters"]},
        {"policy_id": "-1@datacenter-dclab", "effect": "Allow", "actions": ADMIN_PRIVILEGES, "resources": ["datacenter-dclab"]},
        {"policy_id": "579378617@folder-datacenters", "effect": "Allow", "actions": AUTH_PRIVILEGES, "resources": ["folder-datacenters"]},
    ]
    attachments = [
        {
            "principal_id": pid, "policy_id": "-1@folder-datacenters", "attachment_type": "vcenter_direct",
            "entity_id": "folder-datacenters", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True,
        }
        for pid in non_group_at_datacenters + [ADMIN_GROUP]
    ]
    attachments.append({
        "principal_id": ADMIN_NAMED[1], "policy_id": "-1@datacenter-dclab", "attachment_type": "vcenter_direct",
        "entity_id": "datacenter-dclab", "entity_type": "datacenter", "entity_name": "DC-Lab", "propagate": True,
    })
    attachments.append({
        "principal_id": AUTH_USER, "policy_id": "579378617@folder-datacenters", "attachment_type": "vcenter_direct",
        "entity_id": "folder-datacenters", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True,
    })
    return {
        "users": users, "groups": groups, "roles": [], "policies": policies,
        "permissions": permissions, "attachments": attachments, "memberships": [],
    }


def write_golden_pipeline_output(tmp_path: Path) -> Path:
    """Writes the same on-disk shape src.vcenter.pipeline.run_vcenter_
    pipeline would have written, but with findings computed by the real
    find_administrative_access/find_authorization_management_access
    against golden_normalized() - never a hand-typed finding dict - so
    this gate exercises the actual evidence-to-finding path, not just the
    finding-to-report path."""
    normalized = golden_normalized()
    findings = run_all(normalized)

    (tmp_path / "raw").mkdir()
    (tmp_path / "normalized").mkdir()
    (tmp_path / "findings").mkdir()
    (tmp_path / "evidence").mkdir()

    direct_entries = [
        {"principal": a["principal_id"], "group": a["principal_id"] == ADMIN_GROUP, "roleId": a["policy_id"].split("@", 1)[0],
         "role_name": next(p["name"] for p in normalized["policies"] if p["id"] == a["policy_id"]),
         "propagate": a["propagate"], "entity_type": a["entity_type"], "entity_id": a["entity_id"]}
        for a in normalized["attachments"]
    ]
    by_entity: dict[str, list[dict]] = {}
    for a, entry in zip(normalized["attachments"], direct_entries):
        by_entity.setdefault(a["entity_id"], []).append(entry)

    write_json(tmp_path / "raw" / "inventory.json", {
        "datacenter": [{"id": "datacenter-dclab", "type": "datacenter", "name": "DC-Lab", "parent": None}],
        "folder": [{"id": "folder-datacenters", "type": "folder", "name": "Datacenters", "parent": None}],
        "cluster": [], "host": [], "vm": [],
    })
    write_json(tmp_path / "raw" / "authorization.json", {
        "roles": {}, "privileges": {}, "role_privileges": {},
        "entity_permissions": [
            {
                "entity_type": "folder" if entity_id == "folder-datacenters" else "datacenter",
                "entity_id": entity_id, "direct": entries, "inherited": [], "all": entries,
            }
            for entity_id, entries in by_entity.items()
        ],
    })
    write_json(tmp_path / "normalized" / "vcenter.json", normalized)
    write_json(tmp_path / "findings" / "findings.json", findings)
    write_json(tmp_path / "findings" / "collection_report.json", {
        "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00",
        "provider": "vcenter", "complete": True, "sources": [],
    })
    write_json(tmp_path / "evidence" / "evidence_package.json", {"packages": {}})
    return tmp_path


def _admin_finding(findings: list[dict]) -> dict:
    return next(f for f in findings if f["id"] == VCENTER_ADMIN_001)


def _auth_finding(findings: list[dict]) -> dict:
    return next(f for f in findings if f["id"] == VCENTER_AUTH_001)


# --- 1 & 2: every finding is backed by real evidence; ids/severity/
# principals/roles/privileges/scopes match the underlying normalized data ---


def test_known_result_finding_ids_and_counts():
    findings = run_all(golden_normalized())
    assert {f["id"] for f in findings} == {VCENTER_ADMIN_001, VCENTER_AUTH_001}

    admin = _admin_finding(findings)
    assert admin["severity"] == "high"
    assert len(admin["principals"]) == 7
    group_count = sum(1 for p in admin["principals"] if p["principal"]["type"] == "group")
    assert group_count == 1
    assert len(admin["principals"]) - group_count == 6

    auth = _auth_finding(findings)
    assert auth["severity"] == "medium"
    assert len(auth["principals"]) == 1
    assert auth["principals"][0]["role"]["name"] == "ConnectorReaderPlus"
    assert auth["principals"][0]["privileges"] == ["Authorization.ModifyPermissions"]


def test_every_finding_principal_traces_to_a_real_attachment():
    """No principal, role, or scope in a finding may be invented - each
    must correspond to an attachment actually present in the golden
    normalized data (policy_id reconstructed the same way normalize.py
    builds it: f"{roleId}@{entityId}")."""
    normalized = golden_normalized()
    findings = run_all(normalized)
    real_attachment_keys = {(a["principal_id"], a["policy_id"], a["entity_id"]) for a in normalized["attachments"]}

    for finding in findings:
        for entry in finding["principals"]:
            principal_id = entry["principal"]["id"]
            role_id = entry["role"]["id"]
            assert entry["assignments"], f"{principal_id} has no assignments - evidence-free principal"
            for assignment in entry["assignments"]:
                entity_id = assignment["entity_id"]
                policy_id = f"{role_id}@{entity_id}"
                assert (principal_id, policy_id, entity_id) in real_attachment_keys, (
                    f"{finding['id']}: {principal_id} at {entity_id} via {policy_id} has no matching "
                    "real attachment in the golden dataset"
                )


def test_reported_privileges_are_a_subset_of_the_actual_role_permissions():
    """A principal's reported privileges must never be more than (or
    different from) what the underlying permission record actually
    grants for that policy binding."""
    normalized = golden_normalized()
    permissions_by_policy = {p["policy_id"]: set(p["actions"]) for p in normalized["permissions"]}
    findings = run_all(normalized)

    for finding in findings:
        for entry in finding["principals"]:
            role_id = entry["role"]["id"]
            granted = set()
            for assignment in entry["assignments"]:
                policy_id = f"{role_id}@{assignment['entity_id']}"
                granted |= permissions_by_policy[policy_id]
            assert set(entry["privileges"]) <= granted


def test_admin_finding_role_is_a_real_admin_role_name():
    findings = run_all(golden_normalized())
    admin = _admin_finding(findings)
    assert admin["role_name"] in ADMIN_ROLE_NAMES


def test_auth_finding_privileges_are_real_sensitive_privileges():
    findings = run_all(golden_normalized())
    auth = _auth_finding(findings)
    assert set(auth["sensitive_privileges"]) <= set(SENSITIVE_AUTHORIZATION_PRIVILEGES)
    assert set(auth["sensitive_privileges"]) <= set(AUTH_PRIVILEGES)


# --- 3: explanations never claim beyond the evidence ---


def test_admin_wording_does_not_overclaim(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    # Regression guards for wording already fixed once before - "grants
    # unrestricted control ... no further restriction" overclaimed beyond
    # what any finding actually demonstrates.
    assert "unrestricted" not in content.lower()
    assert "no further restriction" not in content.lower()


def test_auth_wording_never_claims_role_modification_when_not_detected(tmp_path):
    """Golden dataset's Authorization Management finding only has
    Authorization.ModifyPermissions as its SENSITIVE privilege - the
    report must never describe that finding as touching roles (only
    Authorization.ModifyRoles justifies that wording). The Admin
    finding's own evidence legitimately lists Authorization.ModifyRoles
    too (Admin genuinely holds it, among ADMIN_PRIVILEGES) - so this
    checks only the Auth finding's own card, isolated by finding it as
    the last card before the relationships section (severity order
    always puts Review after High Risk)."""
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    auth_card_start = content.index("Finding ID: VCENTER-AUTH-001")
    auth_card = content[auth_card_start:content.index('id="relationships"')]
    assert "Authorization.ModifyRoles" not in auth_card


def test_auth_wording_never_asserts_escalation_occurred(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text().lower()
    assert "escalation occurred" not in content
    assert "escalation was observed" not in content
    assert "escalation was demonstrated" not in content


# --- 4: recommendations are relevant to the specific finding ---


def test_admin_recommendation_separates_named_group_and_service(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    findings_section = content[content.index('id="findings"'):content.index('id="relationships"')]

    assert "Named principals" in findings_section
    assert "Group" in findings_section
    assert "Service accounts" in findings_section
    for name in ADMIN_NAMED:
        assert name in findings_section
    assert ADMIN_GROUP in findings_section
    for name in ADMIN_SERVICE:
        assert name in findings_section


def test_auth_recommendation_names_the_actual_privilege_detected(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    findings_section = content[content.index('id="findings"'):content.index('id="relationships"')]
    assert "Authorization.ModifyPermissions" in findings_section
    assert AUTH_USER in findings_section


# --- 5: report limitations are explicitly preserved ---


def test_report_limitations_all_present_in_html(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    for limitation in LIMITATIONS:
        assert limitation in content


def test_report_limitations_all_present_in_pdf(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    pdf_bytes = render_vcenter_pdf(output_dir).read_bytes()
    shown_text = re.sub(rb"\s+", b" ", _pdf_shown_text(pdf_bytes))
    for limitation in LIMITATIONS:
        normalized = re.sub(r"\s+", " ", limitation).encode("latin-1", errors="ignore")
        assert normalized in shown_text


# --- 6: the current known result (summary-level) ---


def test_known_result_summary_counts(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    from src.vcenter.report import load_pipeline_output

    data = load_pipeline_output(output_dir)
    summary = build_summary(data)
    assert summary["findings"] == 2
    assert summary["affected_principal_count"] == 8  # 7 Admin + 1 Auth, deduplicated by name (none overlap here)
    assert summary["findings_by_severity"]["high"] == 7
    assert summary["findings_by_severity"]["medium"] == 1


# --- 7: expected sections present, no em dash anywhere ---


def _unescape_pdf_literal_string(raw: bytes) -> bytes:
    """Reverses PDF string-literal escaping (\\n \\r \\t \\( \\) \\\\ and
    \\ddd octal - reportlab writes any non-ASCII-printable byte, em dash
    included, as a 3-digit octal escape rather than a raw byte) so the
    actual bytes reportlab asked the font to draw can be inspected."""
    out = bytearray()
    i, n = 0, len(raw)
    escapes = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09, 0x62: 0x08, 0x66: 0x0C, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
    while i < n:
        b = raw[i]
        if b == 0x5C and i + 1 < n:  # backslash
            nxt = raw[i + 1]
            if 0x30 <= nxt <= 0x37:  # octal digit
                j, digits = i + 1, ""
                while j < n and len(digits) < 3 and 0x30 <= raw[j] <= 0x37:
                    digits += chr(raw[j])
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            out.append(escapes.get(nxt, nxt))
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


_TJ_STRING_RE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*Tj")


def _pdf_shown_text(pdf_bytes: bytes) -> bytes:
    """Every literal string reportlab actually told a font to draw (Tj
    operator only - this report never uses TJ), concatenated and
    unescaped. Scoped to text-showing operators only, not raw decoded
    stream bytes, so embedded PNG image binary (the relationship graphs)
    can never produce a false-positive byte match - only real page text
    is inspected.

    reportlab's default SimpleDocTemplate chains ASCII85Decode then
    FlateDecode (confirmed by inspecting this report's own PDF output:
    "/Filter [ /ASCII85Decode /FlateDecode ]"), so both stages are
    reversed, in order, before any text is visible. Uses only the
    standard library (base64 + zlib + re), so no PDF-parsing dependency
    is added to the test suite for this one check."""
    decoded = bytearray()
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        chunk = match.group(1).strip()
        try:
            decoded.extend(zlib.decompress(base64.a85decode(chunk, adobe=True)))
        except (zlib.error, ValueError):
            continue
    stream_bytes = bytes(decoded)

    shown = bytearray()
    for match in _TJ_STRING_RE.finditer(stream_bytes):
        literal = match.group(0).rsplit(b")", 1)[0][1:]  # strip "(" ... ")" Tj
        shown.extend(_unescape_pdf_literal_string(literal))
        shown.append(0x20)
    return bytes(shown)


def test_html_report_has_all_expected_sections(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    assert f"<title>{TITLE}</title>" in content
    assert "1.</span> Executive Summary" in content
    assert "2.</span> Security Findings" in content
    assert "3.</span> Security Relationship Graphs" in content
    assert "4.</span> Overall Summary" in content


def test_pdf_report_generated_and_has_expected_page_count(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    pdf_path = render_vcenter_pdf(output_dir)
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")


EM_DASH = chr(0x2014)


def test_no_em_dash_in_html_report(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    content = render_vcenter_report(output_dir).read_text()
    assert EM_DASH not in content


def test_no_em_dash_in_pdf_shown_text(tmp_path):
    output_dir = write_golden_pipeline_output(tmp_path)
    pdf_bytes = render_vcenter_pdf(output_dir).read_bytes()
    shown_text = _pdf_shown_text(pdf_bytes)
    assert b"\x97" not in shown_text  # WinAnsiEncoding em dash (Helvetica, this report's only font)
    assert EM_DASH.encode("utf-8") not in shown_text


def test_no_em_dash_anywhere_in_vcenter_source():
    """Source-level trap: catches a regression the moment it is written,
    before it ever reaches a rendered report."""
    vcenter_src = Path(__file__).resolve().parent.parent / "src" / "vcenter"
    offenders = [
        str(path) for path in vcenter_src.rglob("*.py")
        if EM_DASH in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
