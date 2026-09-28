# vCenter report generation.
"""vCenter-specific HTML/PDF security audit report.

Deliberately separate from src/report/build.py, which is AWS-specific
throughout (title, tooltips, terminology like "IAM Last Accessed"/"Access
Analyzer") - rather than parameterizing that file (and risking AWS wording
leaking into a vCenter report, or vCenter wording leaking into the AWS one),
this module renders its own report from the same kind of already-computed
data src/vcenter/pipeline.py writes to disk.

Reads only already-written pipeline output (raw/inventory.json,
raw/authorization.json, normalized/vcenter.json, findings/findings.json,
evidence/evidence_package.json, findings/collection_report.json) - never
recomputes anything, never reconnects to vCenter.

Deliberately styled after the AWS Sentinel report (src/report/multi_account.py
and the shared visual language) rather than as a separate product: the same
section numbering (1. Executive Summary / 2. Security Findings / 3. Security
Relationship Graphs / 4. Overall Summary), the same severity vocabulary
(HIGH RISK / REVIEW), the same finding-card chrome (colored left border,
severity pill, a deterministic "what was detected" line, a boxed narrative),
and the same relationship-graph palette (src/vcenter/focused_graph.py). A
reader switching the connector from AWS to vCenter should see the same
Sentinel product with different content, not a different report design.

Designed to read like a security assessment, not a serialization of the
vCenter API response:
- one finding card per rule (every affected principal listed inside it, not
  one repetitive card per principal - see src/vcenter/findings.py),
- large privilege lists (e.g. the built-in Admin role's ~464 privileges)
  are shown as a curated few plus a true total count, never dumped in full,
- relationship graphs live only in a dedicated section near the end, one
  full diagram per finding type, showing every actually affected principal
  (never collapsed into a bare count),
- recommendations name the exact privilege(s) actually detected, and ask
  the reader to verify need before suggesting removal for anything that
  looks like an internal vCenter service account.
"""

import html
import json
import re
from datetime import datetime
from io import BytesIO
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image as ReportlabImage
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.vcenter.findings import VCENTER_ADMIN_001, VCENTER_AUTH_001, VCENTER_NOACCESS_001, VCENTER_PRIV_001
from src.vcenter.focused_graph import build_finding_graph, render_focused_graph_png

TITLE = "Sentinel - vCenter Security Audit Report"

LIMITATIONS = (
    "Activity/usage data is not collected for this connector; unused-access analysis is not performed.",
    "Findings are based on collected roles, privileges, permissions, and inventory entities only.",
    "Inventory parent relationships were not available from the REST list responses used to collect this data.",
    "Group membership is not collected, and none is inferred - a group finding names the group, not its members.",
    "This report reflects a single point-in-time collection, not continuous monitoring.",
)

# Privilege ID -> what it actually lets the holder do, used to keep
# recommendation/explanation text specific to the exact privilege detected
# (never described as a different one).
PRIVILEGE_EXPLANATIONS = {
    "Authorization.ModifyPermissions": "modify permission assignments on vCenter objects",
    "Authorization.ModifyRoles": "create or modify the privilege sets that define vCenter roles",
    "Authorization.ReassignRolePermissions": "reassign existing permissions away from a role that is being removed",
    "Sessions.TerminateSession": "terminate other users' active sessions",
    "Global.Settings": "modify vCenter-wide global configuration settings",
    "Host.Config.Settings": "modify a host's configuration settings",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Heuristic only - used purely to phrase the recommendation more carefully
# for what looks like an internal vCenter service account; never used to
# suppress or alter a finding itself.
_UUID_SUFFIX = re.compile(r"-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_SERVICE_ACCOUNT_MARKERS = ("svc", "vpxd", "certificateauthority", "topologysvc", "vmware-vsm", "vsphere-webclient", "vsphere-ui")


def _looks_like_service_account(name: str) -> bool:
    local = name.split("\\")[-1].lower()
    if _UUID_SUFFIX.search(name):
        return True
    return any(marker in local for marker in _SERVICE_ACCOUNT_MARKERS)


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _human_date(raw: str) -> str:
    """A human-readable audit date - never the raw ISO timestamp with
    microseconds and a UTC offset."""
    try:
        return datetime.fromisoformat(str(raw)).strftime("%B %d, %Y")
    except (ValueError, TypeError):
        return str(raw)


def load_pipeline_output(output_dir: Path) -> dict:
    """Read everything src/vcenter/pipeline.py already wrote for this run.
    Raises if a required file is missing - callers should not silently
    regenerate it or reconnect to vCenter."""
    collection_report_path = output_dir / "findings" / "collection_report.json"
    return {
        "inventory": json.loads((output_dir / "raw" / "inventory.json").read_text()),
        "authorization": json.loads((output_dir / "raw" / "authorization.json").read_text()),
        "normalized": json.loads((output_dir / "normalized" / "vcenter.json").read_text()),
        "findings": json.loads((output_dir / "findings" / "findings.json").read_text()),
        "evidence_package": json.loads((output_dir / "evidence" / "evidence_package.json").read_text()),
        "collection_report": json.loads(collection_report_path.read_text()) if collection_report_path.exists() else {},
    }


def build_summary(data: dict) -> dict:
    """The handful of numbers the Executive Summary actually needs - never
    the full normalization/common-model counts (policies, attachments,
    memberships), which belong to the underlying evidence, not the report."""
    inventory = data["inventory"]
    authorization = data["authorization"]
    findings = data["findings"]

    inventory_object_count = sum(len(records) for records in inventory.values())
    direct_count = sum(len(e["direct"]) for e in authorization.get("entity_permissions", []))
    inherited_count = sum(len(e["inherited"]) for e in authorization.get("entity_permissions", []))

    by_severity: dict[str, int] = {}
    affected_principals: set[str] = set()
    for finding in findings:
        severity = finding.get("severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + len(finding["principals"])
        affected_principals.update(p["principal"]["name"] for p in finding["principals"])

    return {
        "inventory_object_count": inventory_object_count,
        "roles": len(authorization.get("roles", {})),
        "direct_permissions": direct_count,
        "inherited_permissions": inherited_count,
        "findings": len(findings),
        "findings_by_severity": by_severity,
        "affected_principal_count": len(affected_principals),
        "affected_principals": sorted(affected_principals),
    }


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 9))


def _severity_label(severity: str) -> str:
    """AWS's own severity vocabulary (HIGH RISK / REVIEW), not the raw
    internal severity string - "medium" reads as "REVIEW", matching the
    same two-tier system the AWS report uses."""
    return "HIGH RISK" if severity == "high" else "REVIEW"


def _access_label(entry: dict) -> str:
    types = {a["attachment_type"] for a in entry["assignments"]}
    if types == {"vcenter_direct"}:
        return "Direct"
    if types == {"vcenter_inherited"}:
        return "Inherited"
    return "Direct + Inherited"


def _split_by_account_type(principals: list[dict]) -> tuple[list[dict], list[dict]]:
    service_accounts = [p for p in principals if _looks_like_service_account(p["principal"]["name"])]
    named = [p for p in principals if p not in service_accounts]
    return named, service_accounts


def _principal_kind(entry: dict) -> str:
    """named / group / service - shared classification used by both the
    Affected Principals table (_group_principals_by_kind) and the Admin
    recommendation (_admin_recommendation) - a group is never folded into
    "named" in either place. The Auth Management recommendation
    (_auth_recommendation) still uses its own two-way split
    (_split_by_account_type) since no group has ever appeared in that
    finding's real data; if one ever does, it would currently be
    classified as "named" there, same as before this change."""
    principal = entry["principal"]
    if principal["type"] == "group":
        return "group"
    if _looks_like_service_account(principal["name"]):
        return "service"
    return "named"


_PRINCIPAL_KIND_LABELS = (
    ("named", "Named principals"),
    ("group", "Groups"),
    ("service", "Service/platform accounts"),
)


def _group_principals_by_kind(principals: list[dict]) -> list[tuple[str, list[dict]]]:
    """principals split into named/group/service buckets, in a fixed
    display order, skipping any bucket with nothing in it - a finding made
    up of only one kind (the common case) still renders as one plain
    table; a mixed finding (e.g. Administrative Access: named users, the
    Administrators group, and internal service accounts) shows which
    principals are which without adding a column or widening the table.
    Never infers group membership - a group stays exactly one row, itself,
    never expanded into member rows that were never collected."""
    buckets: dict[str, list[dict]] = {"named": [], "group": [], "service": []}
    for entry in principals:
        buckets[_principal_kind(entry)].append(entry)
    return [(label, buckets[key]) for key, label in _PRINCIPAL_KIND_LABELS if buckets[key]]


def _principal_count_note(principals: list[dict]) -> str | None:
    """Only rendered when a finding's Affected Principals includes a group
    - clarifies that the count is authorization subjects/assignments, not
    a headcount of human users, and that group membership was not
    collected (see LIMITATIONS). Returns None when every principal is a
    user, so the common case adds no extra text."""
    group_count = sum(1 for p in principals if p["principal"]["type"] == "group")
    if group_count == 0:
        return None
    subject_noun = "authorization subject" if len(principals) == 1 else "authorization subjects"
    group_noun = "group" if group_count == 1 else "groups"
    return (
        f"{len(principals)} {subject_noun} (assignments), including {group_count} {group_noun}. "
        f"Group membership was not collected, so this is not a count of individual human users."
    )


def _admin_recommendation(principals: list[dict]) -> list[tuple[str, str]]:
    """(label, text) pairs, one per principal kind actually present (named
    user / group / service account - see _principal_kind) - never one
    paragraph covering more than one kind, and the group is never folded
    into "Named principals": the right action differs for a named human
    user, the group itself (whose membership was never collected), and an
    internal service account."""
    by_kind: dict[str, list[dict]] = {"named": [], "group": [], "service": []}
    for entry in principals:
        by_kind[_principal_kind(entry)].append(entry)

    items = []
    if by_kind["named"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["named"])
        items.append(
            (
                "Named principals",
                f"{names}: confirm each genuinely requires full administrative control. If not, "
                f"replace with a narrower custom role holding only the privileges required.",
            )
        )
    if by_kind["group"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["group"])
        items.append(
            (
                "Group",
                f"{names}: confirm this group genuinely requires full administrative control. Group "
                f"membership was not collected - verify who actually belongs to it before changing or "
                f"removing this assignment.",
            )
        )
    if by_kind["service"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["service"])
        items.append(
            (
                "Service accounts",
                f"{names}: verify the corresponding service actually requires administrative access "
                f"before making any change. Built-in platform services holding this role are often "
                f"expected by design; only reduce access after confirming it is unnecessary.",
            )
        )
    return items


def _auth_recommendation(finding: dict) -> list[tuple[str, str]]:
    privilege_list = ", ".join(finding["sensitive_privileges"])
    named, service_accounts = _split_by_account_type(finding["principals"])
    items = [("Review", f"Confirm each affected principal actually needs {privilege_list}.")]
    if named:
        names = ", ".join(p["principal"]["name"] for p in named)
        items.append(("Named principals", f"{names}: remove this privilege if not required."))
    if service_accounts:
        names = ", ".join(p["principal"]["name"] for p in service_accounts)
        items.append(("Service accounts", f"{names}: verify the service actually needs this privilege before removing it."))
    return items


def _priv_recommendation(finding: dict) -> list[tuple[str, str]]:
    """(label, text) pairs, one per principal kind actually present - the
    same three-way named/group/service split _admin_recommendation uses
    (_principal_kind), never _split_by_account_type's two-way split, which
    would misclassify a group as a named principal. The real data for this
    finding is a group (platform-admins), so this must not repeat that
    earlier bug."""
    privilege_list = ", ".join(finding["high_impact_privileges"])
    by_kind: dict[str, list[dict]] = {"named": [], "group": [], "service": []}
    for entry in finding["principals"]:
        by_kind[_principal_kind(entry)].append(entry)

    items = [("Review", f"Confirm each affected principal actually needs {privilege_list}.")]
    if by_kind["named"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["named"])
        items.append(("Named principals", f"{names}: remove this privilege if not required."))
    if by_kind["group"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["group"])
        items.append(
            (
                "Group",
                f"{names}: confirm this group genuinely requires this privilege. Group membership was "
                f"not collected - verify who actually belongs to it before changing or removing this "
                f"assignment.",
            )
        )
    if by_kind["service"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["service"])
        items.append(("Service accounts", f"{names}: verify the corresponding service actually needs this privilege before removing it."))
    return items


def _no_access_recommendation(finding: dict) -> list[tuple[str, str]]:
    """Verification wording throughout - never a removal/least-privilege
    recommendation like every other vCenter finding in this report, since
    removing an explicit No Access assignment widens access rather than
    narrowing it."""
    by_kind: dict[str, list[dict]] = {"named": [], "group": [], "service": []}
    for entry in finding["principals"]:
        by_kind[_principal_kind(entry)].append(entry)

    items = []
    if by_kind["named"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["named"])
        items.append(("Named principals", f"{names}: confirm this restriction is intentional and still matches the intended access boundary."))
    if by_kind["group"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["group"])
        items.append(
            (
                "Group",
                f"{names}: confirm this restriction is intentional. Group membership was not collected "
                f"- verify who is actually affected by it.",
            )
        )
    if by_kind["service"]:
        names = ", ".join(p["principal"]["name"] for p in by_kind["service"])
        items.append(("Service accounts", f"{names}: confirm this restriction does not unintentionally block a service that needs access here."))
    return items


def _admin_why_it_matters(finding: dict) -> str:
    return (
        f"The built-in {finding['role_name']} role provides broad administrative control over "
        f"vCenter and objects within each holder's assigned scope, spanning authorization, "
        f"inventory, certificate, and configuration privileges "
        f"({finding['total_privilege_count']} privileges in total)."
    )


def _auth_why_it_matters(finding: dict) -> str:
    """One evidence-grounded sentence per privilege actually detected
    (never a different privilege than what is present), plus one shared
    closing sentence describing the privilege's potential without
    asserting that an escalation was observed or demonstrated - no finding
    here is derived from an actual escalation attempt, only from the
    privilege being present."""
    privileges = finding["sensitive_privileges"]
    clauses = [
        f"{p} allows the principal to {PRIVILEGE_EXPLANATIONS.get(p, 'modify vCenter authorization')} "
        f"within the scope where the privilege is effective."
        for p in privileges
    ]
    return (
        f"{' '.join(clauses)} Depending on the roles available to assign, this may enable broader "
        "access to itself or other principals. No privilege escalation is asserted here."
    )


def _priv_why_it_matters(finding: dict) -> str:
    """Mirrors _auth_why_it_matters: one evidence-grounded sentence per
    high-impact privilege actually detected (never a different privilege
    than what is present), plus one closing sentence describing what sets
    this category apart from an object-scoped privilege - it is still
    granted at a specific entity like any other permission, but what it
    lets the holder do reaches vCenter's own configuration or session
    state, not just objects within that entity's scope."""
    privileges = finding["high_impact_privileges"]
    clauses = [
        f"{p} allows the principal to {PRIVILEGE_EXPLANATIONS.get(p, 'affect vCenter configuration or sessions')} "
        f"within the scope where the privilege is effective."
        for p in privileges
    ]
    return (
        f"{' '.join(clauses)} Unlike a privilege scoped to individual inventory objects, these affect "
        "vCenter's own configuration or active sessions directly."
    )


def _no_access_why_it_matters(finding: dict) -> str:
    return (
        "An explicit No Access assignment overrides whatever access would otherwise apply to that "
        "principal at the entity where it is set - vCenter evaluates it ahead of any inherited or "
        "group-based grant for that principal at that entity. This is a restriction, not a grant: it "
        "removes access rather than providing it, and is reported here so it can be verified as "
        "intentional, not asserted as a vulnerability."
    )


def _finding_narrative(finding: dict) -> tuple[str, list[tuple[str, str]]]:
    """(why_it_matters, recommendation_items) - both specific to the exact
    privileges/principals in this finding, never a generic fixed template
    disconnected from what was actually detected. recommendation_items is a
    list of (label, text) pairs - named principals and service accounts are
    always kept as separate items, never merged into one paragraph."""
    if finding["id"] == VCENTER_ADMIN_001:
        return _admin_why_it_matters(finding), _admin_recommendation(finding["principals"])
    if finding["id"] == VCENTER_AUTH_001:
        return _auth_why_it_matters(finding), _auth_recommendation(finding)
    if finding["id"] == VCENTER_NOACCESS_001:
        return _no_access_why_it_matters(finding), _no_access_recommendation(finding)
    if finding["id"] == VCENTER_PRIV_001:
        return _priv_why_it_matters(finding), _priv_recommendation(finding)
    raise ValueError(f"Unknown vCenter finding id: {finding['id']}")


def _evidence_text(finding: dict) -> str:
    if finding["id"] == VCENTER_ADMIN_001:
        notable = ", ".join(finding["notable_privileges"])
        if finding["total_privilege_count"] > len(finding["notable_privileges"]):
            return f"{finding['total_privilege_count']} privileges granted in total. Notable: {notable}, and others (full list retained in the underlying evidence data)."
        return f"{finding['total_privilege_count']} privileges granted: {notable}."
    if finding["id"] == VCENTER_AUTH_001:
        return f"Privilege(s) granted: {', '.join(finding['sensitive_privileges'])}."
    if finding["id"] == VCENTER_NOACCESS_001:
        return "No privileges are granted by this role - it is an explicit deny of any otherwise-applicable access at the entity where it is assigned."
    if finding["id"] == VCENTER_PRIV_001:
        return f"Privilege(s) granted: {', '.join(finding['high_impact_privileges'])}."
    raise ValueError(f"Unknown vCenter finding id: {finding['id']}")


CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f4f5f7; color: #172B4D; }
header { background: #172B4D; color: #fff; padding: 22px 32px; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; }
header h1 { margin: 0 0 4px 0; font-size: 21px; }
header .header-sub { margin: 0; opacity: 0.8; font-size: 12.5px; }
header .header-meta { text-align: right; font-size: 12px; opacity: 0.9; line-height: 1.6; }
main { max-width: 980px; margin: 0 auto; padding: 24px 32px 64px; }
section { background: #fff; border-radius: 8px; padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.08); }
h2 { font-size: 18px; margin: 0 0 4px 0; font-weight: 700; }
h2 .section-num { color: #6B778C; font-weight: 400; }
h3 { font-size: 13px; font-weight: 700; color: #172B4D; margin: 16px 0 6px 0; }
table { width: 100%; border-collapse: collapse; margin-top: 6px; }
td, th { text-align: left; padding: 5px 8px; border-bottom: 1px solid #EBECF0; font-size: 12.5px; }
th { color: #6B778C; font-weight: 600; }
.note { font-size: 12.5px; color: #6B778C; margin: 4px 0 12px 0; }
ul.limitations { margin: 4px 0 0 0; padding-left: 18px; }
ul.limitations li { margin-bottom: 4px; font-size: 12.5px; }

/* Severity vocabulary */
.severity-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; }
.severity-high { background: #FFEBE6; color: #BF2600; }
.severity-medium { background: #FFF0B3; color: #974F0C; }
.severity-group-heading { font-size: 13.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; margin: 18px 0 10px 0; }
.severity-group-heading.high { color: #BF2600; }
.severity-group-heading.review { color: #974F0C; }

/* Executive summary metrics table (AWS-style header row + big-number row) */
table.metrics { margin: 14px 0 18px 0; }
table.metrics th { text-align: center; text-transform: uppercase; letter-spacing: 0.03em; font-size: 10.5px; border-bottom: 1px solid #DFE1E6; }
table.metrics td { text-align: center; font-size: 25px; font-weight: 700; border-bottom: none; padding-top: 8px; color: #172B4D; }
table.metrics td.risk { color: #BF2600; }
table.metrics td.review { color: #974F0C; }

/* Key risks */
ul.key-risks { margin: 6px 0 0 0; padding-left: 18px; }
ul.key-risks li { margin-bottom: 6px; font-size: 13px; }
ul.key-risks .ptype { color: #6B778C; font-size: 11.5px; }
ul.key-risks .rules { color: #6B778C; }

.principal-kind-label { font-size: 11.5px; font-weight: 700; color: #6B778C; margin: 10px 0 2px 0; }

/* Finding cards */
.finding { background: #fff; border: 1px solid #DFE1E6; border-left: 5px solid #DE350B; border-radius: 8px;
  padding: 14px 18px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
.finding.medium { border-left-color: #FFAB00; }
.finding-header { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.finding-title { font-size: 16px; font-weight: 700; }
.finding-meta { font-size: 12px; color: #6B778C; margin-top: 3px; }
.eyebrow { font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: #6B778C; margin: 12px 0 4px 0; font-style: normal; }
.narrative-box { background: #EAF0FF; border: 1px solid #C1D4F5; border-radius: 8px; padding: 12px 16px; margin-top: 12px; }
.narrative-box .eyebrow { color: #0052CC; }
.recommendation-item { margin-bottom: 6px; font-size: 13px; }
.recommendation-item b { color: #172B4D; }

/* Relationship graphs */
.view { margin-bottom: 26px; }
.view img { max-width: 100%; width: 100%; border: 1px solid #EBECF0; border-radius: 6px; background: #fff; }
.view-label { font-weight: 700; margin-bottom: 4px; font-size: 15px; }
"""


def _friendly_entity_type(entity_type: str) -> str:
    """A human-readable object kind - vCenter's raw moref type string
    (vim.Datacenter, vim.Folder) is internal API naming a security reviewer
    has no reason to see; this report always shows the object kind itself
    (Datacenter, Folder), never the vim.* wrapper."""
    return entity_type.rsplit(".", 1)[-1] if entity_type else entity_type


def _entities_in_scope(finding: dict) -> list[dict]:
    """Every distinct entity affected by this finding, deduplicated across
    all its principals, with its real name/type and how many principals
    reach it directly vs. via inheritance - so every entity is actually
    named somewhere in the report, never collapsed into a count-only
    summary or mislabeled as a different entity."""
    by_entity: dict[str, dict] = {}
    for entry in finding["principals"]:
        for assignment in entry["assignments"]:
            entity_id = assignment["entity_id"]
            record = by_entity.setdefault(
                entity_id,
                {"name": assignment["entity_name"] or entity_id, "type": _friendly_entity_type(assignment["entity_type"]), "direct": 0, "inherited": 0},
            )
            if assignment["attachment_type"] == "vcenter_direct":
                record["direct"] += 1
            else:
                record["inherited"] += 1
    return sorted(by_entity.values(), key=lambda e: e["name"])


def _entities_in_scope_table_html(finding: dict) -> str:
    entities = _entities_in_scope(finding)
    rows = "".join(
        f"<tr><td>{_esc(e['name'])}</td><td>{_esc(e['type'])}</td>"
        f"<td>{e['direct']}</td><td>{e['inherited']}</td></tr>"
        for e in entities
    )
    return (
        "<table><tr><th>Entity</th><th>Type</th><th>Direct grants</th><th>Inherited grants</th></tr>"
        f"{rows}</table>"
    )


_PRINCIPALS_TABLE_HEADER = "<tr><th>Principal</th><th>Type</th><th>Role</th><th>Scope</th><th>Access</th></tr>"


def _principal_rows_html(principals: list[dict]) -> str:
    return "".join(
        f"<tr><td>{_esc(p['principal']['name'])}</td><td>{_esc(p['principal']['type'])}</td>"
        f"<td>{_esc(p['role']['name'])}</td><td>{_esc(p['assignments_summary'])}</td>"
        f"<td>{_esc(_access_label(p))}</td></tr>"
        for p in principals
    )


def _principals_table_html(principals: list[dict]) -> str:
    """One table when every affected principal is the same kind (named /
    group / service - the common case); a small labeled table per kind
    when a finding mixes them (e.g. Administrative Access), so a reviewer
    can immediately tell a group row from a named user or service account
    without a new column widening the table (see _group_principals_by_kind)."""
    groups = _group_principals_by_kind(principals)
    if len(groups) <= 1:
        return f"<table>{_PRINCIPALS_TABLE_HEADER}{_principal_rows_html(principals)}</table>"
    parts = [
        f'<div class="principal-kind-label">{_esc(label)}</div>'
        f"<table>{_PRINCIPALS_TABLE_HEADER}{_principal_rows_html(group)}</table>"
        for label, group in groups
    ]
    return "".join(parts)


def _recommendation_html(items: list[tuple[str, str]]) -> str:
    rows = "".join(f'<div class="recommendation-item"><b>{_esc(label)}:</b> {_esc(text)}</div>' for label, text in items)
    return rows


def _finding_meta_html(finding: dict) -> str:
    principals = finding["principals"]
    roles = sorted({p["role"]["name"] for p in principals})
    return (
        f'<div class="finding-meta">Finding ID: {_esc(finding["id"])}'
        f' &nbsp;&middot;&nbsp; Affected authorization subjects: {len(principals)}'
        f' &nbsp;&middot;&nbsp; Role: {_esc(", ".join(roles))}</div>'
    )


def _finding_section_html(finding: dict) -> str:
    severity = finding.get("severity", "low")
    why_it_matters, recommendation_items = _finding_narrative(finding)

    return f"""
    <div class="finding {'medium' if severity == 'medium' else ''}">
      <div class="finding-header">
        <span class="finding-title">{_esc(finding["title"])}</span>
        <span class="severity-badge severity-{_esc(severity)}">{_esc(_severity_label(severity))}</span>
      </div>
      {_finding_meta_html(finding)}

      <div class="eyebrow">What Was Detected (deterministic)</div>
      <p>{_esc(finding["detail"])}</p>

      <h3>Affected Principals</h3>
      {f'<p class="note">{_esc(_principal_count_note(finding["principals"]))}</p>' if _principal_count_note(finding["principals"]) else ''}
      {_principals_table_html(finding["principals"])}

      <h3>Entities In Scope</h3>
      {_entities_in_scope_table_html(finding)}

      <div class="narrative-box">
        <div class="eyebrow">Why This Matters</div>
        <p>{_esc(why_it_matters)}</p>
        <div class="eyebrow">Recommendation</div>
        {_recommendation_html(recommendation_items)}
        <div class="eyebrow">Evidence</div>
        <p>{_esc(_evidence_text(finding))}</p>
      </div>
    </div>
    """


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _severity_groups(findings: list[dict]) -> list[tuple[str, list[dict]]]:
    """Findings bucketed into "high" / "review" (never a raw severity
    string), in severity order - the same two-tier grouping the AWS report
    uses for its "HIGH RISK FINDINGS (n)" / "REVIEW FINDINGS (n)" section
    headings."""
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for finding in _sorted_findings(findings):
        bucket = "high" if finding.get("severity") == "high" else "review"
        if bucket not in buckets:
            buckets[bucket] = []
            order.append(bucket)
        buckets[bucket].append(finding)
    return [(bucket, buckets[bucket]) for bucket in order]


def _severity_group_heading_html(bucket: str, findings: list[dict]) -> str:
    count = sum(len(f["principals"]) for f in findings)
    noun = "authorization subject" if count == 1 else "authorization subjects"
    label = "High Risk" if bucket == "high" else "Review"
    return f'<div class="severity-group-heading {bucket}">{_esc(label.upper())} FINDINGS ({count} {noun})</div>'


def _findings_section_html(findings: list[dict]) -> str:
    if not findings:
        return """
        <section id="findings">
          <h2><span class="section-num">2.</span> Security Findings</h2>
          <p>No security findings were produced by this collection. Every vCenter security rule
            executed against the collected authorization data and found nothing to report.</p>
        </section>
        """
    body_parts = []
    for bucket, group in _severity_groups(findings):
        body_parts.append(_severity_group_heading_html(bucket, group))
        body_parts.extend(_finding_section_html(f) for f in group)
    return f"""
    <section id="findings">
      <h2><span class="section-num">2.</span> Security Findings</h2>
      <p class="note">Ordered by severity. Each card separates what deterministic code detected
        from why it matters and what to do about it.</p>
      {''.join(body_parts)}
    </section>
    """


def _relationship_views_html(findings: list[dict]) -> str:
    if not findings:
        return ""
    blocks = []
    for finding in _sorted_findings(findings):
        view = build_finding_graph(finding, deny=finding["id"] == VCENTER_NOACCESS_001)
        png_bytes = render_focused_graph_png(view["graph"])
        encoded = _b64(png_bytes)
        blocks.append(
            f"""
            <div class="view">
              <div class="view-label">{_esc(view['label'])} - Relationship Graph</div>
              <p class="note">{_esc(finding['detail'])}</p>
              <img src="data:image/png;base64,{encoded}" alt="{_esc(view['label'])}">
            </div>
            """
        )
    return f"""
    <section id="relationships">
      <h2><span class="section-num">3.</span> Security Relationship Graphs</h2>
      <p class="note">Every principal, role, privilege, and entity relevant to a finding above -
        colors mark risk; arrows show role assignment, privilege membership, and where each grant
        applies. One diagram per finding type.</p>
      {''.join(blocks)}
    </section>
    """


def _metrics(summary: dict, findings: list[dict]) -> tuple[int, int, int]:
    """(total_findings, high_risk, review) - total_findings is the number
    of finding cards/types (2: Administrative Access, Authorization
    Management Access), never a principal-instance count, so it can never
    be read as "8 findings" when the Findings by Type table plainly lists
    two rows. High Risk / Review are principal-level counts (how many
    affected principals fall in each severity), always kept visually and
    numerically distinct from both the finding count and affected_
    principal_count (unique principals)."""
    total_findings = len(findings)
    total_principal_instances = sum(len(f["principals"]) for f in findings)
    high = sum(len(f["principals"]) for f in findings if f.get("severity") == "high")
    return total_findings, high, total_principal_instances - high


def _metrics_note(summary: dict, findings: list[dict]) -> str | None:
    """Clarifies "Affected Principals" when it includes a group - the
    metric itself is unchanged (still every distinct principal named in
    any finding), but a group is not a headcount of individual users, and
    group membership was never collected (see LIMITATIONS). Returns None
    when no group appears among the affected principals, so the common
    case adds no extra text under the metrics table."""
    principal_type_by_name: dict[str, str] = {}
    for finding in findings:
        for entry in finding["principals"]:
            principal_type_by_name[entry["principal"]["name"]] = entry["principal"]["type"]
    group_count = sum(1 for name in summary["affected_principals"] if principal_type_by_name.get(name) == "group")
    if group_count == 0:
        return None
    noun = "group" if group_count == 1 else "groups"
    return (
        f"Affected Principals counts distinct authorization subjects (named users, service "
        f"accounts, and groups), including {group_count} {noun}. Group membership was not "
        f"collected, so this is not a count of individual human users."
    )


def _metrics_table_html(summary: dict, findings: list[dict]) -> str:
    total, high, review = _metrics(summary, findings)
    return f"""
    <table class="metrics">
      <tr><th>Total Findings</th><th>Affected Principals</th><th>High Risk</th><th>Review</th></tr>
      <tr>
        <td>{total}</td>
        <td>{summary['affected_principal_count']}</td>
        <td class="risk">{high}</td>
        <td class="review">{review}</td>
      </tr>
    </table>
    """


def _findings_by_type_table_html(findings: list[dict]) -> str:
    rows = "".join(
        f'<tr><td>{_esc(f["title"])}</td>'
        f'<td><span class="severity-badge severity-{_esc(f.get("severity", "low"))}">{_esc(_severity_label(f.get("severity", "low")))}</span></td>'
        f"<td>{len(f['principals'])}</td></tr>"
        for f in _sorted_findings(findings)
    )
    if not rows:
        rows = '<tr><td colspan="3">No findings.</td></tr>'
    return f"<table><tr><th>Finding Type</th><th>Severity</th><th>Affected Principals</th></tr>{rows}</table>"


_KEY_RISK_NAME_LIMIT = 32


def _short_key_risk_name(name: str) -> str:
    """Executive-summary-only abbreviation for a long machine/service
    identifier (e.g. a UUID-suffixed vpxd-* service account) - the full
    identifier always remains in the Affected Principals table and the
    underlying evidence, never here. Short, human-chosen names
    (Administrator, dev-alice, svc-connector) are well under the limit and
    are never touched."""
    if len(name) <= _KEY_RISK_NAME_LIMIT:
        return name
    return name[:28] + "..."


def _key_risks(findings: list[dict]) -> list[dict]:
    """Every affected principal, once, with every rule it matched joined
    together - a principal caught by more than one rule gets one combined
    bullet, never two near-identical ones (mirrors src/report/multi_
    account.py's _key_risk_groups combining logic for AWS)."""
    order: list[str] = []
    by_name: dict[str, dict] = {}
    for finding in _sorted_findings(findings):
        for entry in finding["principals"]:
            name = entry["principal"]["name"]
            if name not in by_name:
                by_name[name] = {"principal": entry["principal"], "titles": []}
                order.append(name)
            by_name[name]["titles"].append(finding["title"])
    return [by_name[name] for name in order]


def _key_risks_html(findings: list[dict]) -> str:
    risks = _key_risks(findings)
    if not risks:
        return "<p>No key risks identified.</p>"
    items = "".join(
        f'<li><b title="{_esc(r["principal"]["name"])}">{_esc(_short_key_risk_name(r["principal"]["name"]))}</b> '
        f'<span class="ptype">({_esc(r["principal"]["type"])})</span> '
        f'<span class="rules">- {_esc(" / ".join(r["titles"]))}</span></li>'
        for r in risks
    )
    return f'<ul class="key-risks">{items}</ul>'


def _header_html(collection_report: dict, summary: dict) -> str:
    audit_date = _human_date(collection_report.get("finished_at", "unknown"))
    status = "Complete" if collection_report.get("complete", True) else "Completed with gaps"
    return f"""
    <header>
      <div class="header-main">
        <h1>{_esc(TITLE)}</h1>
        <p class="header-sub">Read-only vCenter authorization audit - inventory, roles, privileges, and permissions.</p>
      </div>
      <div class="header-meta">
        <div>Generated: {_esc(audit_date)}</div>
        <div>Audit status: {_esc(status)}</div>
        <div>Inventory objects reviewed: {summary['inventory_object_count']}</div>
      </div>
    </header>
    """


def _executive_summary_html(summary: dict, findings: list[dict]) -> str:
    return f"""
    <section id="summary">
      <h2><span class="section-num">1.</span> Executive Summary</h2>
      <p class="note">This audit is read-only. It collected vCenter authorization data (roles,
        privileges, and permissions) and identified security-relevant authorization conditions.
        Findings are decided entirely by deterministic code.</p>
      {_metrics_table_html(summary, findings)}
      {f'<p class="note">{_esc(_metrics_note(summary, findings))}</p>' if _metrics_note(summary, findings) else ''}
      <h3>Findings by Type</h3>
      {_findings_by_type_table_html(findings)}
      <h3>Key Risks</h3>
      {_key_risks_html(findings)}
      <h3>Audit Scope</h3>
      <p class="note">{summary["roles"]} roles and {summary["direct_permissions"] + summary["inherited_permissions"]}
        permission assignments reviewed across {summary["inventory_object_count"]} inventory objects.</p>
    </section>
    """


def _overall_summary_html(summary: dict, findings: list[dict]) -> str:
    items = "".join(f"<li>{_esc(item)}</li>" for item in LIMITATIONS)
    return f"""
    <section id="overall">
      <h2><span class="section-num">4.</span> Overall Summary</h2>
      {_metrics_table_html(summary, findings)}
      {f'<p class="note">{_esc(_metrics_note(summary, findings))}</p>' if _metrics_note(summary, findings) else ''}
      <h3>Findings by Type</h3>
      {_findings_by_type_table_html(findings)}
      <h3>Key Risks</h3>
      {_key_risks_html(findings)}
      <p class="note">This audit reviewed one vCenter environment. Full finding detail and
        relationship graphs are in the sections above.</p>
      <h3>Report Notes</h3>
      <ul class="limitations">{items}</ul>
    </section>
    """


def render_vcenter_report(output_dir: Path, data: dict | None = None) -> Path:
    """Render vcenter_security_audit_report.html into output_dir, from
    already-written pipeline output. Never reconnects to vCenter."""
    if data is None:
        data = load_pipeline_output(output_dir)
    summary = build_summary(data)
    findings = data["findings"]

    body = f"""
{_header_html(data["collection_report"], summary)}
<main>
  {_executive_summary_html(summary, findings)}
  {_findings_section_html(findings)}
  {_relationship_views_html(findings)}
  {_overall_summary_html(summary, findings)}
</main>
"""

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(TITLE)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>"""

    output_path = output_dir / "vcenter_security_audit_report.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return output_path


# --- PDF ---

_TABLE_STYLE = TableStyle(
    [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172B4D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EBECF0")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
)

_CELL_STYLE = ParagraphStyle("cell", fontSize=8, leading=10)

# Explicit, non-italic bold heading style for every subsection - never a
# reportlab "HeadingN" style, whose italics/weight varies by level.
_H3_STYLE = ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=11, leading=14, spaceBefore=8, spaceAfter=3, textColor=colors.HexColor("#172B4D"))
_NOTE_STYLE = ParagraphStyle("noteStyle", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#6B778C"))
_EYEBROW_STYLE = ParagraphStyle("eyebrow", fontName="Helvetica-Bold", fontSize=8, spaceBefore=6, spaceAfter=2, textColor=colors.HexColor("#6B778C"))
_EYEBROW_ON_BLUE_STYLE = ParagraphStyle("eyebrowBlue", parent=_EYEBROW_STYLE, textColor=colors.HexColor("#0052CC"))
_METRIC_NUMBER_STYLE = ParagraphStyle("metricNumber", fontName="Helvetica-Bold", fontSize=22, alignment=1, textColor=colors.HexColor("#172B4D"))
_METRIC_NUMBER_RISK_STYLE = ParagraphStyle("metricNumberRisk", parent=_METRIC_NUMBER_STYLE, textColor=colors.HexColor("#BF2600"))
_METRIC_NUMBER_REVIEW_STYLE = ParagraphStyle("metricNumberReview", parent=_METRIC_NUMBER_STYLE, textColor=colors.HexColor("#974F0C"))
_METRIC_LABEL_STYLE = ParagraphStyle("metricLabel", fontName="Helvetica", fontSize=8, alignment=1, textColor=colors.HexColor("#6B778C"))
_TITLE_STYLE = ParagraphStyle("bannerTitle", fontName="Helvetica-Bold", fontSize=15.5, leading=19, textColor=colors.white, spaceAfter=3)
_SUBTITLE_STYLE = ParagraphStyle("bannerSubtitle", fontName="Helvetica", fontSize=9.5, leading=12, textColor=colors.HexColor("#C7D3E8"))
_META_STYLE = ParagraphStyle("bannerMeta", fontName="Helvetica", fontSize=9, textColor=colors.white, alignment=2, leading=13)
_FINDING_TITLE_STYLE = ParagraphStyle("findingTitle", fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=colors.HexColor("#172B4D"))
_FINDING_META_STYLE = ParagraphStyle("findingMeta", fontName="Helvetica", fontSize=8.5, textColor=colors.HexColor("#6B778C"), spaceBefore=2, spaceAfter=4)
_SEVERITY_GROUP_STYLE_HIGH = ParagraphStyle("severityGroupHigh", fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#BF2600"), spaceBefore=12, spaceAfter=6)
_SEVERITY_GROUP_STYLE_REVIEW = ParagraphStyle("severityGroupReview", parent=_SEVERITY_GROUP_STYLE_HIGH, textColor=colors.HexColor("#974F0C"))
_CONTINUED_STYLE = ParagraphStyle("continued", fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#6B778C"), spaceBefore=4, spaceAfter=4)

_PAGE_TOP_MARGIN = 0.5 * inch
_PAGE_BOTTOM_MARGIN = 0.6 * inch
_PAGE_SIDE_MARGIN = 0.6 * inch
_CONTENT_WIDTH = LETTER[0] - _PAGE_SIDE_MARGIN * 2
_PAGE_USABLE_HEIGHT = LETTER[1] - _PAGE_TOP_MARGIN - _PAGE_BOTTOM_MARGIN


def _flowable_height(flowable) -> float:
    """A flowable's own natural height, for deciding ahead of time whether
    a finding's content will fit one page - reportlab only tells you this
    by asking the flowable to wrap itself against the real content width,
    with an intentionally oversized available height so it reports its
    true size rather than being cut short.

    Paragraph.wrap() alone under-reports: spaceBefore/spaceAfter on a
    ParagraphStyle (used throughout this report's H3/eyebrow/meta styles)
    is added by the frame while actually flowing content, not by wrap()
    itself - so it has to be added back in here, or every one-page-fits
    estimate below silently comes in short.

    KeepTogether.wrap() needs a live canvas (only present during the real
    doc.build()) and raises outside one - so a KeepTogether is measured by
    summing its own wrapped content instead of calling wrap() on it
    directly, recursively (a KeepTogether can itself contain another, e.g.
    the "<Title> - Continued" label bound to the recommendation box)."""
    if isinstance(flowable, KeepTogether):
        return sum(_flowable_height(f) for f in flowable._content)
    height = flowable.wrap(_CONTENT_WIDTH, _PAGE_USABLE_HEIGHT * 10)[1]
    style = getattr(flowable, "style", None)
    return height + getattr(style, "spaceBefore", 0) + getattr(style, "spaceAfter", 0)


def _cell(text) -> Paragraph:
    """Wrap table cell text in a Paragraph so long values (principal names
    with long service-account suffixes, entity names, role names) wrap
    within the column instead of overflowing into neighboring cells - a
    plain string in a reportlab Table cell does not wrap on its own."""
    return Paragraph(html.escape(str(text)), _CELL_STYLE)


def _pdf_table(rows: list[tuple], header: tuple, col_widths: list[float]) -> Table:
    wrapped_rows = [tuple(_cell(value) for value in row) for row in rows]
    table = Table([header] + wrapped_rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(_TABLE_STYLE)
    return table


_PRINCIPAL_CELL_STYLE = ParagraphStyle("principalCell", fontName="Helvetica", fontSize=7.5, leading=9)


def _principal_cell(name: str) -> Paragraph:
    """The Principal column cell - always the full identifier (this table
    never abbreviates; only the executive Key Risks section does), in its
    own wider, slightly smaller-font style so a long hyphenated service-
    account identifier (e.g. a UUID-suffixed vpxd-* name) has more room to
    wrap cleanly than the original narrow column allowed.

    A zero-width space inserted after each hyphen was tried here to hint a
    break point there, but Helvetica's base14 Type1 encoding has no glyph
    for U+200B - reportlab rendered it as a visible black box between
    every hyphen instead of nothing, which looked far worse than the
    plain wrap it was meant to fix. Reverted: the wider column and smaller
    font already give reportlab's own wrapping enough room to land in a
    reasonable place without adding characters that don't render safely."""
    return Paragraph(html.escape(name), _PRINCIPAL_CELL_STYLE)


def _pdf_principals_table(principals: list[dict]) -> Table:
    """Built directly (not via _pdf_table) so the Principal column can use
    its own wider width and hyphen-aware wrapping while the other columns
    stay compact - full identifiers are never truncated here.

    Type and Role got more room than their first pass: at the original
    0.45in/0.75in, a short single-word value with no space to wrap at
    (e.g. "group", or a custom role name like "ConnectorReaderPlus") had
    nowhere to break except mid-word, which reportlab does by cutting the
    word at an arbitrary character - real content ("group" -> "grou"/"p")
    caught this on visual inspection. Scope/Access gave up the same amount
    of width in return; their own values (a sentence, or "Direct" /
    "Inherited" / "Direct + Inherited") already wrap cleanly at a space,
    so a narrower column there does not reproduce the same problem."""
    header = ("Principal", "Type", "Role", "Scope", "Access")
    rows = [
        (
            _principal_cell(p["principal"]["name"]),
            _cell(p["principal"]["type"]),
            _cell(p["role"]["name"]),
            _cell(p["assignments_summary"]),
            _cell(_access_label(p)),
        )
        for p in principals
    ]
    col_widths = [3.5 * inch, 0.6 * inch, 1.4 * inch, 1.2 * inch, 0.55 * inch]
    table = Table([header] + rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(_TABLE_STYLE)
    return table


_PRINCIPAL_KIND_LABEL_STYLE = ParagraphStyle(
    "principalKindLabel", fontName="Helvetica-Bold", fontSize=8.5, textColor=colors.HexColor("#6B778C"), spaceBefore=6, spaceAfter=2
)


def _pdf_principals_tables(principals: list[dict]) -> list:
    """One table when every affected principal is the same kind (the
    common case, unchanged); a small labeled table per kind when a
    finding mixes named users, a group, and/or service accounts - see
    _group_principals_by_kind. Returned as a flat flowable list so the
    caller can splice it into the finding's story/measurement list like
    any other flowable."""
    groups = _group_principals_by_kind(principals)
    if len(groups) <= 1:
        return [_pdf_principals_table(principals)]
    flowables: list = []
    for label, group in groups:
        flowables.append(Paragraph(label, _PRINCIPAL_KIND_LABEL_STYLE))
        flowables.append(_pdf_principals_table(group))
    return flowables


def _pdf_banner(collection_report: dict, summary: dict) -> Table:
    audit_date = _human_date(collection_report.get("finished_at", "unknown"))
    status = "Complete" if collection_report.get("complete", True) else "Completed with gaps"
    left = [
        Paragraph(TITLE, _TITLE_STYLE),
        Paragraph("Read-only vCenter authorization audit", _SUBTITLE_STYLE),
    ]
    right = Paragraph(
        f"Generated: {html.escape(audit_date)}<br/>Audit status: {html.escape(status)}<br/>"
        f"Inventory objects reviewed: {summary['inventory_object_count']}",
        _META_STYLE,
    )
    table = Table([[left, right]], colWidths=[4.6 * inch, 1.7 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#172B4D")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
                ("LEFTPADDING", (0, 0), (0, 0), 16),
                ("RIGHTPADDING", (1, 0), (1, 0), 16),
            ]
        )
    )
    return table


def _pdf_metrics_table(summary: dict, findings: list[dict]) -> Table:
    total, high, review = _metrics(summary, findings)
    labels = ["Total Findings", "Affected Principals", "High Risk", "Review"]
    numbers = [
        Paragraph(str(total), _METRIC_NUMBER_STYLE),
        Paragraph(str(summary["affected_principal_count"]), _METRIC_NUMBER_STYLE),
        Paragraph(str(high), _METRIC_NUMBER_RISK_STYLE),
        Paragraph(str(review), _METRIC_NUMBER_REVIEW_STYLE),
    ]
    label_paragraphs = [Paragraph(label, _METRIC_LABEL_STYLE) for label in labels]
    col_width = 6.3 * inch / 4
    table = Table([label_paragraphs, numbers], colWidths=[col_width] * 4, rowHeights=[20, 34])
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#DFE1E6")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 1), (-1, 1), 8),
            ]
        )
    )
    return table


def _pdf_findings_by_type_table(findings: list[dict]) -> Table:
    rows = [(f["title"], _severity_label(f.get("severity", "low")), str(len(f["principals"]))) for f in _sorted_findings(findings)]
    return _pdf_table(rows, ("Finding Type", "Severity", "Affected Principals"), [3.0 * inch, 1.5 * inch, 1.8 * inch])


def _pdf_key_risks(findings: list[dict], styles) -> list:
    risks = _key_risks(findings)
    if not risks:
        return [Paragraph("No key risks identified.", styles["Normal"])]
    flowables = []
    for r in risks:
        name = html.escape(_short_key_risk_name(r["principal"]["name"]))
        text = f"<b>{name}</b> ({html.escape(r['principal']['type'])}) - {html.escape(' / '.join(r['titles']))}"
        flowables.append(Paragraph(f"&bull; {text}", styles["Normal"]))
    return flowables


def _pdf_severity_group_heading(bucket: str, findings: list[dict]) -> Paragraph:
    count = sum(len(f["principals"]) for f in findings)
    noun = "authorization subject" if count == 1 else "authorization subjects"
    label = "High Risk" if bucket == "high" else "Review"
    style = _SEVERITY_GROUP_STYLE_HIGH if bucket == "high" else _SEVERITY_GROUP_STYLE_REVIEW
    return Paragraph(f"{label.upper()} FINDINGS ({count} {noun})", style)


def _pdf_boxed(content: list) -> Table:
    """A light-blue boxed group of flowables - the PDF equivalent of the
    HTML narrative box. Kept small and single-purpose (why-it-matters,
    recommendation, and evidence each get their own box, not one combined
    box) so a page break can fall between boxes instead of being forced to
    push one large atomic block (and everything after it) entirely onto
    the next page, which was leaving a large blank gap at the bottom of
    the previous page."""
    table = Table([[content]], colWidths=[6.3 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EAF0FF")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#C1D4F5")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    return table


def _pdf_narrative_boxes(finding: dict, styles) -> tuple[Table, Table]:
    """(why_box, recommendation_box) - two boxes, not three. Recommendation
    and Evidence are combined into one box: splitting all three into
    independent atomic boxes let a page break fall between Recommendation
    and Evidence, stranding a lone "EVIDENCE" heading with a couple of
    lines at the top of the next page with no context above it - Evidence
    is short and never carries useful meaning by itself, so it always
    rides along with Recommendation (substantial enough that the pair
    reads as a coherent unit wherever it lands)."""
    why_it_matters, recommendation_items = _finding_narrative(finding)

    why_box = _pdf_boxed([Paragraph("WHY THIS MATTERS", _EYEBROW_ON_BLUE_STYLE), Paragraph(html.escape(why_it_matters), styles["Normal"])])

    recommendation_content = [Paragraph("RECOMMENDATION", _EYEBROW_ON_BLUE_STYLE)]
    for label, text in recommendation_items:
        recommendation_content.append(Paragraph(f"<b>{html.escape(label)}:</b> {html.escape(text)}", styles["Normal"]))
        recommendation_content.append(Spacer(1, 3))
    recommendation_content.append(Paragraph("EVIDENCE", _EYEBROW_ON_BLUE_STYLE))
    recommendation_content.append(Paragraph(html.escape(_evidence_text(finding)), styles["Normal"]))
    recommendation_box = _pdf_boxed(recommendation_content)

    return why_box, recommendation_box


def _finding_header_block(finding: dict, styles) -> list:
    """Title/severity badge/meta/What-Was-Detected - the atomic minimum
    _pdf_finding_card wraps in KeepTogether. Extracted as its own function
    so its height can also be measured directly (summing _flowable_height
    over these plain flowables) without needing a live canvas - a bare
    KeepTogether.wrap() call outside doc.build() raises, since it looks for
    a canvas that only exists during real rendering."""
    severity = finding.get("severity", "low")
    badge_color = colors.HexColor("#BF2600") if severity == "high" else colors.HexColor("#974F0C")
    accent_color = colors.HexColor("#DE350B") if severity == "high" else colors.HexColor("#FFAB00")

    accent_bar = Table([[""]], colWidths=[6.6 * inch], rowHeights=[4])
    accent_bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), accent_color), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))

    badge_style = ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=9, textColor=badge_color, alignment=2)
    header_row = Table(
        [[Paragraph(html.escape(finding["title"]), _FINDING_TITLE_STYLE), Paragraph(_severity_label(severity), badge_style)]],
        colWidths=[4.7 * inch, 1.4 * inch],
    )
    header_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 0)]))

    roles = ", ".join(sorted({p["role"]["name"] for p in finding["principals"]}))
    meta = Paragraph(
        f"Finding ID: {html.escape(finding['id'])} &nbsp;&middot;&nbsp; "
        f"Affected authorization subjects: {len(finding['principals'])} &nbsp;&middot;&nbsp; Role: {html.escape(roles)}",
        _FINDING_META_STYLE,
    )

    return [
        accent_bar,
        Spacer(1, 8),
        header_row,
        meta,
        Paragraph("WHAT WAS DETECTED (DETERMINISTIC)", _EYEBROW_STYLE),
        Paragraph(html.escape(finding["detail"]), styles["Normal"]),
    ]


def _finding_header_block_height(finding: dict, styles) -> float:
    return sum(_flowable_height(f) for f in _finding_header_block(finding, styles))


def _pdf_finding_card(styles, finding: dict, preceding_overhead: float = 0.0) -> list:
    """One finding as a list of ordinary story flowables, not one giant
    nested Table - a reportlab Table cell containing a flowable list is
    atomic (it never splits across a page break), so wrapping an entire
    multi-table finding in one outer Table forced the whole card onto the
    next page whenever it did not fit the remaining space, leaving a
    severity heading stranded above a nearly blank page. Only the small
    title/severity/meta header is kept atomic (via KeepTogether) so a
    title is never separated from its severity pill; the principal table,
    entity table, and narrative box below it are ordinary flowables that
    reportlab can place - and split, with repeatRows=1 keeping their own
    header row visible - across a page boundary like any other content.

    The colored accent bar is a separate thin Table above the header,
    the PDF equivalent of the HTML card's border-left.

    preceding_overhead: the height of whatever the caller already placed
    on this page directly above the finding (a severity-group heading,
    and for the very first finding also the "2. Security Findings"
    section heading/intro) - without it, the one-page-fits check below
    would measure against a full blank page, when the real remaining
    space on the page is smaller by exactly that much.
    """
    header_block = _finding_header_block(finding, styles)

    entity_rows = [(e["name"], e["type"], str(e["direct"]), str(e["inherited"])) for e in _entities_in_scope(finding)]

    principal_count_note = _principal_count_note(finding["principals"])
    flowables = [
        KeepTogether(header_block),
        Spacer(1, 4),
        Paragraph("Affected Principals", _H3_STYLE),
        *([Paragraph(html.escape(principal_count_note), _NOTE_STYLE)] if principal_count_note else []),
        *_pdf_principals_tables(finding["principals"]),
        Spacer(1, 6),
        Paragraph("Entities In Scope", _H3_STYLE),
        _pdf_table(entity_rows, ("Entity", "Type", "Direct", "Inherited"), [2.0 * inch, 1.0 * inch, 0.8 * inch, 0.9 * inch]),
        Spacer(1, 6),
    ]
    why_box, recommendation_box = _pdf_narrative_boxes(finding, styles)
    flowables.append(why_box)
    flowables.append(Spacer(1, 4))

    # Each finding already starts at the top of a fresh page (see the
    # caller), but a finding with a wide principal table and a long
    # recommendation can still genuinely exceed one page's height. When
    # our own measurement says everything up to and including Recommendation
    # will not actually fit, "<Title> - Continued" is inserted right there
    # so a reader who lands on the next page sees which finding they are
    # still reading, instead of a bare "RECOMMENDATION" with no heading
    # above it. When it does fit (the common case), nothing extra is added.
    # KeepTogether.wrap() needs a live canvas (only present during the
    # real doc.build()), so header_block's own flowables are measured
    # directly here rather than through the KeepTogether wrapper.
    measurable = header_block + flowables[1:]
    content_before_recommendation_height = sum(_flowable_height(f) for f in measurable)
    available_height = _PAGE_USABLE_HEIGHT - preceding_overhead
    if content_before_recommendation_height + _flowable_height(recommendation_box) > available_height:
        # KeepTogether, not two separate appends: a plain Paragraph
        # appended before recommendation_box would just print wherever it
        # itself fits - often the bottom of the CURRENT page, with
        # Recommendation still moving to the next page beneath it, which
        # defeats the point. Binding them together guarantees the label
        # lands immediately above Recommendation wherever the break falls.
        continued = Paragraph(f"{html.escape(finding['title'])} - Continued", _CONTINUED_STYLE)
        flowables.append(KeepTogether([continued, recommendation_box]))
    else:
        flowables.append(recommendation_box)
    flowables.append(Spacer(1, 16))
    return flowables


_GRAPH_MAX_WIDTH = 6.6 * inch
# A reportlab-Image scale below this shrinks the graph's fixed-size PNG
# text (rendered at 13px, see focused_graph.py) well past what the rest
# of this report already treats as legible (the smallest text anywhere
# else in the PDF, _CELL_STYLE, is 8pt - this floor keeps a combined-page
# graph no smaller than that). If either graph would fall below it, both
# graphs get their own full page instead of being crammed together.
_GRAPH_MIN_READABLE_SCALE = 0.42
_GRAPH_ENTRY_GAP = 10
# A genuine cushion, not just a hedge against float rounding: a fit with
# only a point or two of slack is exactly what "cramped" means, and would
# also be one content tweak away from silently overflowing again. Combining
# is only worth it when there is real headroom; otherwise the one-page-per-
# graph fallback (deliberately larger, not a consolation prize) is the more
# robust and honestly better-looking choice.
_GRAPH_FIT_SAFETY_MARGIN = 24
_GRAPH_SECTION_INTRO = (
    "Every principal, role, privilege, and entity relevant to a finding above - colors mark "
    "risk; arrows show role assignment, privilege membership, and where each grant applies. "
    "One diagram per finding type."
)


def _graph_pngs(findings: list[dict]) -> list[tuple[dict, dict, bytes, int, int]]:
    """(finding, view, png_bytes, width, height) for every finding, in
    severity order - computed once so both the combined-page attempt and
    the one-per-page fallback below read the same rendered images."""
    sized = []
    for finding in _sorted_findings(findings):
        view = build_finding_graph(finding, deny=finding["id"] == VCENTER_NOACCESS_001)
        png_bytes = render_focused_graph_png(view["graph"])
        width, height = PILImage.open(BytesIO(png_bytes)).size
        sized.append((finding, view, png_bytes, width, height))
    return sized


def _graph_flowables(finding: dict, view: dict, png_bytes: bytes, width: int, height: int, scale: float) -> list:
    return [
        Paragraph(f"{view['label']} - Relationship Graph", _H3_STYLE),
        Paragraph(html.escape(finding["detail"]), _NOTE_STYLE),
        Spacer(1, 6),
        ReportlabImage(BytesIO(png_bytes), width=width * scale, height=height * scale),
    ]


def _graph_group(finding: dict, view: dict, png_bytes: bytes, width: int, height: int, scale: float) -> Table:
    """heading + description + image, kept from ever splitting across a
    page break - a borderless single-cell Table, not KeepTogether. Plain
    sequential flowables let reportlab place the heading/description text
    on one page and the image (which cannot itself be split) alone on the
    next once the two together didn't quite fit; KeepTogether would
    prevent that, but KeepTogether.wrap() reports a "does not fit"
    sentinel height when asked to measure itself outside a live document
    frame, which is exactly what the one-page-fits check below needs to
    do ahead of time. A Table's wrap() doesn't have that problem and
    still keeps its cell's content atomic, so it is used for both the
    real measurement and the real placement - never two different
    mechanisms disagreeing with each other again."""
    table = Table([[_graph_flowables(finding, view, png_bytes, width, height, scale)]], colWidths=[_CONTENT_WIDTH])
    table.setStyle(TableStyle([(pad, (0, 0), (-1, -1), 0) for pad in ("TOPPADDING", "BOTTOMPADDING", "LEFTPADDING", "RIGHTPADDING")]))
    return table


def _graph_natural_scale(width: int) -> float:
    # Capped at 1.0 (never enlarged) - a small graph (e.g. a single
    # three-node privilege chain) is already legible at its own rendered
    # resolution; stretching it up toward the width ceiling was exactly
    # what made a small graph consume most of a page by itself, leaving no
    # room for another one beside it.
    return min(_GRAPH_MAX_WIDTH / width, 1.0)


def _joint_page_scales(
    items: list[tuple[dict, dict, bytes, int, int]], budget: float
) -> list[float] | None:
    """Scales for every item in `items` if they can all share ONE page
    together, else None. Every item is shrunk by the same proportion at
    once (not just whichever was added last) - two graphs that are each a
    little too tall to fit next to each other at full size can still often
    both fit if both shrink together, which shrinking only the newer one
    (leaving the earlier one at full size) would miss entirely. Never
    shrinks below _GRAPH_MIN_READABLE_SCALE - if the joint shrink needed
    to fit would go below that, this page cannot hold this exact set.
    """
    if not items:
        return []

    natural_scales = [_graph_natural_scale(width) for *_rest, width, _height in items]
    text_overheads = []
    image_heights = []
    for (finding, view, png_bytes, width, height), natural in zip(items, natural_scales):
        group_height = _flowable_height(_graph_group(finding, view, png_bytes, width, height, natural))
        text_overheads.append(group_height - height * natural)
        image_heights.append(height)
    gaps_total = _GRAPH_ENTRY_GAP * (len(items) - 1)

    natural_total = sum(text_overheads) + sum(h * s for h, s in zip(image_heights, natural_scales)) + gaps_total
    if natural_total <= budget:
        return natural_scales

    image_weight = sum(h * s for h, s in zip(image_heights, natural_scales))
    if image_weight <= 0:
        return None
    shrink = (budget - sum(text_overheads) - gaps_total) / image_weight
    if shrink <= 0:
        return None
    scales = [natural * shrink for natural in natural_scales]
    if min(scales) < _GRAPH_MIN_READABLE_SCALE:
        return None
    return scales


def _pack_relationship_view_pages(
    sized: list[tuple[dict, dict, bytes, int, int]], styles
) -> list[list[tuple[dict, dict, bytes, int, int, float]]]:
    """Greedy bin-packing: add graphs to the current page as long as the
    whole set placed so far still jointly fits (see _joint_page_scales);
    start a new page only once the next graph genuinely does not fit
    alongside what is already queued. Returns one list of (finding, view,
    png_bytes, width, height, scale) per page.

    This replaces an earlier all-or-nothing choice (either every graph
    shares one page, or every graph gets its own full page) that forced a
    small graph onto an otherwise near-empty page whenever even one OTHER
    graph in the report was too large to share a page with it. Now however
    many actually fit - jointly shrinking together where needed - share a
    page, and only a graph that is genuinely too big for any page even
    alone is shrunk down to the legibility floor as a last resort.
    """
    full_page = LETTER[1] - _PAGE_TOP_MARGIN - _PAGE_BOTTOM_MARGIN
    section_overhead = (
        _flowable_height(Paragraph("3. Security Relationship Graphs", styles["Heading1"]))
        + _flowable_height(Paragraph(_GRAPH_SECTION_INTRO, _NOTE_STYLE))
        + 8  # spacer between the section intro and the first graph
    )
    first_budget = full_page - section_overhead - _GRAPH_FIT_SAFETY_MARGIN
    later_budget = full_page - _GRAPH_FIT_SAFETY_MARGIN

    pages: list[list[tuple[dict, dict, bytes, int, int, float]]] = []
    current: list[tuple[dict, dict, bytes, int, int]] = []
    budget = first_budget

    def _finalize_current() -> None:
        if not current:
            return
        scales = _joint_page_scales(current, budget)
        if scales is None:
            # Only reachable for a single graph that does not fit even
            # alone on its own page at the legibility floor - shrink it
            # only as far as this page's real budget requires rather than
            # drop below the floor, so it still renders, just tight.
            finding, view, png_bytes, width, height = current[0]
            natural = _graph_natural_scale(width)
            group_height = _flowable_height(_graph_group(finding, view, png_bytes, width, height, natural))
            text_overhead = group_height - height * natural
            scales = [max(_GRAPH_MIN_READABLE_SCALE, (budget - text_overhead) / height)]
        pages.append([(*entry, scale) for entry, scale in zip(current, scales)])

    for entry in sized:
        if _joint_page_scales(current + [entry], budget) is not None:
            current.append(entry)
            continue
        _finalize_current()
        current = [entry]
        budget = later_budget

    _finalize_current()
    return pages


def _pdf_relationship_views(story: list, styles, findings: list[dict]) -> None:
    if not findings:
        return
    story.append(PageBreak())
    story.append(Paragraph("3. Security Relationship Graphs", styles["Heading1"]))
    story.append(Paragraph(_GRAPH_SECTION_INTRO, _NOTE_STYLE))
    story.append(Spacer(1, 8))

    sized = _graph_pngs(findings)
    pages = _pack_relationship_view_pages(sized, styles)

    for page_index, page in enumerate(pages):
        if page_index > 0:
            story.append(PageBreak())
        for entry_index, (finding, view, png_bytes, width, height, scale) in enumerate(page):
            if entry_index > 0:
                story.append(Spacer(1, _GRAPH_ENTRY_GAP))
            story.append(_graph_group(finding, view, png_bytes, width, height, scale))


def render_vcenter_pdf(output_dir: Path, data: dict | None = None) -> Path:
    """Render vcenter_security_audit_report.pdf into output_dir."""
    if data is None:
        data = load_pipeline_output(output_dir)
    summary = build_summary(data)
    findings = data["findings"]

    output_path = output_dir / "vcenter_security_audit_report.pdf"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    story = [_pdf_banner(data["collection_report"], summary), Spacer(1, 14)]

    story.append(Paragraph("1. Executive Summary", styles["Heading1"]))
    story.append(
        Paragraph(
            "This audit is read-only. It collected vCenter authorization data (roles, privileges, "
            "and permissions) and identified security-relevant authorization conditions. Findings "
            "are decided entirely by deterministic code.",
            _NOTE_STYLE,
        )
    )
    story.append(Spacer(1, 8))
    story.append(_pdf_metrics_table(summary, findings))
    metrics_note = _metrics_note(summary, findings)
    if metrics_note:
        story.append(Spacer(1, 6))
        story.append(Paragraph(html.escape(metrics_note), _NOTE_STYLE))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Findings by Type", _H3_STYLE))
    story.append(_pdf_findings_by_type_table(findings))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Key Risks", _H3_STYLE))
    story.extend(_pdf_key_risks(findings, styles))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Audit Scope", _H3_STYLE))
    story.append(
        Paragraph(
            f"{summary['roles']} roles and {summary['direct_permissions'] + summary['inherited_permissions']} "
            f"permission assignments reviewed across {summary['inventory_object_count']} inventory objects.",
            _NOTE_STYLE,
        )
    )

    story.append(PageBreak())
    section_heading = Paragraph("2. Security Findings", styles["Heading1"])
    section_note = Paragraph("Ordered by severity.", _NOTE_STYLE)
    story.append(section_heading)
    story.append(section_note)
    story.append(Spacer(1, 6))
    section_overhead = _flowable_height(section_heading) + _flowable_height(section_note) + 6

    if not findings:
        story.append(
            Paragraph(
                "No security findings were produced by this collection. Every vCenter security rule "
                "executed against the collected authorization data and found nothing to report.",
                styles["Normal"],
            )
        )
    else:
        # Findings are packed onto pages as they actually fit, instead of
        # each one always starting a fresh page - a short finding (e.g. No
        # Access Override: one principal, one entity) no longer leaves the
        # remainder of its own page blank just because the finding before
        # it happened to end near a page boundary. A severity-group
        # heading is still never left orphaned alone at a page bottom
        # (measured together with its first finding's header below), and a
        # finding whose own header would not fit what remains still starts
        # a fresh page rather than being split awkwardly - only the choice
        # of WHEN to force that break changed, not the coherence guarantee
        # itself (KeepTogether(header_block) inside _pdf_finding_card, and
        # its own measured "Continued" label for a finding too long for one
        # page, are both untouched).
        remaining = _PAGE_USABLE_HEIGHT - section_overhead
        first_group = True
        for bucket, group in _severity_groups(findings):
            severity_heading = _pdf_severity_group_heading(bucket, group)
            heading_height = _flowable_height(severity_heading)
            first_finding_header_height = _finding_header_block_height(group[0], styles)

            if not first_group and heading_height + first_finding_header_height > remaining:
                story.append(PageBreak())
                remaining = _PAGE_USABLE_HEIGHT

            story.append(severity_heading)
            remaining -= heading_height
            first_group = False

            for index, finding in enumerate(group):
                header_height = _finding_header_block_height(finding, styles)

                if index > 0 and header_height > remaining:
                    story.append(PageBreak())
                    remaining = _PAGE_USABLE_HEIGHT

                preceding_overhead = _PAGE_USABLE_HEIGHT - remaining
                card = _pdf_finding_card(styles, finding, preceding_overhead=preceding_overhead)
                story.extend(card)
                card_height = sum(_flowable_height(f) for f in card)
                if card_height >= remaining:
                    # This card spilled across at least one page break of
                    # its own - approximate what is left on whichever page
                    # it ended on, so the next heading/finding's fit check
                    # measures against the real remaining space rather than
                    # assuming either a full or an empty page.
                    overflow = (card_height - remaining) % _PAGE_USABLE_HEIGHT
                    remaining = _PAGE_USABLE_HEIGHT - overflow
                else:
                    remaining -= card_height

    _pdf_relationship_views(story, styles, findings)

    story.append(PageBreak())
    story.append(Paragraph("4. Overall Summary", styles["Heading1"]))
    story.append(Spacer(1, 8))
    story.append(_pdf_metrics_table(summary, findings))
    overall_metrics_note = _metrics_note(summary, findings)
    if overall_metrics_note:
        story.append(Spacer(1, 6))
        story.append(Paragraph(html.escape(overall_metrics_note), _NOTE_STYLE))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings by Type", _H3_STYLE))
    story.append(_pdf_findings_by_type_table(findings))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Key Risks", _H3_STYLE))
    story.extend(_pdf_key_risks(findings, styles))
    story.append(Spacer(1, 10))

    limitations_block = [Paragraph("Report Notes", _H3_STYLE)]
    for item in LIMITATIONS:
        limitations_block.append(Paragraph(f"&bull; {html.escape(item)}", ParagraphStyle("limitation", parent=styles["Normal"], fontSize=9)))
    story.append(KeepTogether(limitations_block))

    SimpleDocTemplate(str(output_path), pagesize=LETTER, topMargin=_PAGE_TOP_MARGIN, bottomMargin=_PAGE_BOTTOM_MARGIN, leftMargin=_PAGE_SIDE_MARGIN, rightMargin=_PAGE_SIDE_MARGIN).build(story)
    return output_path
