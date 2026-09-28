"""vCenter connector pipeline: auth -> collect -> normalize -> vCenter
findings -> evidence -> report.

Reuses build_evidence_package unchanged - already a plain function operating
on the common model, not on anything AWS-specific. Findings come from
src.vcenter.findings.run_all (VCENTER-ADMIN-001, VCENTER-AUTH-001), not the
shared AWS rules: rules.broad_permission_and_administrative_access and
indirect_privilege_path both proved to be structural no-ops against real
vCenter data (vCenter's Admin role never has actions=["*"], and no
CAN_ASSUME-equivalent construct exists) - see src/vcenter/CLAUDE.md Phase 8.5.
Nothing in src/analysis/rules.py was modified; this module simply calls a
different function.

No full-vCenter graph is ever built or rendered here (see
src/vcenter/CLAUDE.md Phase 9): evidence.build_evidence_package still
requires a graph argument for its CAN_ASSUME-based relationship lookup, but
vCenter data never produces CAN_ASSUME edges (no assume-role construct), so
an empty graph is passed - correct and equivalent, without generating or
storing a full inventory-wide graph anywhere. Findings carry their own
focused relationship graphs instead (src/vcenter/focused_graph.py), rendered
only in the report's dedicated Relationship Views section.

No AI explanation stage: the grouped finding schema (one finding per rule,
covering every matching principal - see findings.py) does not map onto
ai/explain.py's one-finding-per-principal contract, and the report's
narrative sections (Why This Matters, Recommendation) are deterministic
templates keyed to the actual detected privileges, not AI-generated - see
src/vcenter/report.py. This keeps the report's explanations consistent and
requires no OpenAI call for this connector.

Activity is deliberately never touched here: no activity-dependent rule is
called, and evidence.build_evidence_package always receives empty
last_accessed/cloudtrail/analyzer inputs. vCenter's capability manifest
declares activity/unused_access NOT_SUPPORTED (src/vcenter/CLAUDE.md section
6) - feeding empty activity data into an activity-dependent rule would make
every vCenter permission look "unused", a proven false signal, not a missing
one.
"""

from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from src.evidence.build import build_evidence_package
from src.util.io import write_json
from src.util.status import CollectionStatus
from src.vcenter import auth, authorization_collector, inventory_collector
from src.vcenter.findings import run_all as run_vcenter_findings
from src.vcenter.normalize import normalize
from src.vcenter.report import render_vcenter_pdf, render_vcenter_report
from src.vcenter.rest_client import VCenterRestClient
from src.vcenter.soap_client import VCenterSoapClient

PROVIDER = "vcenter"


def _flatten_inventory(inventory: dict) -> list[dict]:
    """inventory_collector's per-type dict -> the flat entity list
    authorization_collector.collect() expects (it only reads each record's
    "type"/"id", extra keys like "name"/"parent" are simply ignored)."""
    return [record for records in inventory.values() for record in records]


def _collection_report(started: datetime, statuses: list[CollectionStatus]) -> dict:
    return {
        "started_at": started,
        "finished_at": datetime.now(timezone.utc),
        "provider": PROVIDER,
        "complete": all(s.succeeded for s in statuses),
        "sources": [s.as_dict() for s in statuses],
    }


def run_vcenter_pipeline(output_dir: Path) -> dict:
    """Authenticate, collect, normalize, and run the vCenter findings/
    evidence/report pipeline against a real vCenter.

    No activity-dependent rule is ever called; evidence's activity-shaped
    inputs are always empty, never fabricated (see module docstring). No
    full-vCenter graph is built, stored, or rendered (see module docstring).
    """
    started = datetime.now(timezone.utc)
    statuses: list[CollectionStatus] = []

    raw_dir = output_dir / "raw"
    normalized_dir = output_dir / "normalized"
    findings_dir = output_dir / "findings"
    evidence_dir = output_dir / "evidence"

    session = auth.login()
    try:
        rest_client = VCenterRestClient(base_url=session.rest_base_url, session_id=session.rest_session_id)
        soap_client = VCenterSoapClient(service_instance=session.soap_service_instance)

        inventory, inventory_status = inventory_collector.collect(rest_client)
        statuses.append(inventory_status)
        if not inventory_status.succeeded:
            write_json(findings_dir / "collection_report.json", _collection_report(started, statuses))
            return {"provider": PROVIDER, "complete": False, "statuses": statuses}
        write_json(raw_dir / "inventory.json", inventory)

        entities = _flatten_inventory(inventory)
        authorization, authorization_status = authorization_collector.collect(soap_client, entities)
        statuses.append(authorization_status)
        if not authorization_status.succeeded:
            write_json(findings_dir / "collection_report.json", _collection_report(started, statuses))
            return {"provider": PROVIDER, "complete": False, "statuses": statuses}
        write_json(raw_dir / "authorization.json", authorization)

        normalized = normalize(inventory, authorization)
        write_json(normalized_dir / "vcenter.json", normalized)

        # vCenter-specific deterministic findings only (VCENTER-ADMIN-001,
        # VCENTER-AUTH-001). No activity-dependent rule is called - activity
        # is NOT_SUPPORTED for vCenter.
        findings = run_vcenter_findings(normalized)
        write_json(findings_dir / "findings.json", findings)

        # Evidence needs a graph argument for its CAN_ASSUME-based
        # relationship lookup, but vCenter never produces CAN_ASSUME edges -
        # an empty graph is correct and avoids building or storing a
        # full-vCenter graph anywhere (see module docstring).
        empty_graph = nx.DiGraph()
        evidence_package = build_evidence_package(normalized, empty_graph, {}, {}, {}, region=PROVIDER)
        write_json(evidence_dir / "evidence_package.json", evidence_package)

        collection_report = _collection_report(started, statuses)
        write_json(findings_dir / "collection_report.json", collection_report)

        html_report_path = render_vcenter_report(output_dir)
        pdf_report_path = render_vcenter_pdf(output_dir)

        return {
            "provider": PROVIDER,
            "complete": collection_report["complete"],
            "statuses": statuses,
            "findings_path": findings_dir / "findings.json",
            "report_html_path": html_report_path,
            "report_pdf_path": pdf_report_path,
            "finding_count": len(findings),
        }
    finally:
        auth.logout(session)
