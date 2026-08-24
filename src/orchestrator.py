"""Multi-account orchestration: Management Account -> PROD/DEV -> combined findings.

Wires together src/aws/auth.py's assume_role, src/aws/organizations_collector.py,
and src/main.py's run_pipeline — none of which change here. This module adds
no new AWS permission, no new collector, and no cross-account security
correlation: it only assumes a role per target account, runs the existing,
unmodified audit pipeline once per account, and combines the results.

Discovery via Organizations confirms/reports what's in the org; it does not
choose which accounts get audited — that list is the fixed TARGET_ACCOUNTS
below, matching this POC's approved scope (PROD and DEV only).
"""

import json
from pathlib import Path

from src import config
from src.aws import auth, organizations_collector
from src.main import run_pipeline
from src.report.multi_account import render_multi_account_report
from src.util.io import write_json

TARGET_ACCOUNTS = {
    "PROD": "328865868092",
    "DEV": "587762853586",
}
ROLE_NAME = "AuditReadOnlyRole"


def audit_account(base_session, label: str, account_id: str) -> dict:
    """Assume the role in one account, run the existing pipeline, never raise.

    A failure here — at authentication or during collection — is returned
    as a result record, not an exception, so one account's problem can
    never stop the other account from being audited.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"

    try:
        target_session = auth.assume_role(base_session, role_arn)
        identity = auth.verify_identity(target_session)
    except auth.AuthError as exc:
        return {
            "account_label": label,
            "account_id": account_id,
            "status": "failed",
            "failure_stage": "authentication",
            "error": str(exc),
        }

    try:
        pipeline_result = run_pipeline(target_session, identity, config.account_output_root(label))
    except Exception as exc:  # noqa: BLE001 — a pipeline failure must not abort the other account
        return {
            "account_label": label,
            "account_id": account_id,
            "status": "failed",
            "failure_stage": "collection",
            "error": str(exc),
        }

    return {
        "account_label": label,
        "account_id": account_id,
        "status": "success",
        "finding_count": pipeline_result.get("finding_count", 0),
        "pipeline_result": pipeline_result,
    }


def _tag_findings(findings_path: Path, account_id: str, account_name: str) -> list[dict]:
    """Read one account's untouched findings.json and return tagged copies.

    Does not modify findings_path on disk. Each returned dict is the
    original finding's fields (principal, policy_id, attribution, rule,
    detail) plus account_id/account_name added on top.
    """
    original_findings = json.loads(Path(findings_path).read_text())
    return [{**finding, "account_id": account_id, "account_name": account_name} for finding in original_findings]


def audit_all_accounts(base_session) -> dict:
    """Discover accounts (for confirmation), then audit exactly the configured targets."""
    _discovered, organizations_status = organizations_collector.collect(base_session)

    results = [audit_account(base_session, label, account_id) for label, account_id in TARGET_ACCOUNTS.items()]

    combined_findings: list[dict] = []
    for result in results:
        if result["status"] != "success":
            continue
        findings_path = result["pipeline_result"].get("findings_path")
        if findings_path:
            combined_findings.extend(_tag_findings(findings_path, result["account_id"], result["account_label"]))

    management_identity = base_session.client("sts").get_caller_identity()

    aggregate = {
        "management_account_id": management_identity["Account"],
        "organizations_status": organizations_status.as_dict(),
        "accounts": results,
        "accounts_succeeded": sum(1 for r in results if r["status"] == "success"),
        "accounts_failed": sum(1 for r in results if r["status"] == "failed"),
        "findings": combined_findings,
        "total_findings": len(combined_findings),
    }

    combined_findings_path = write_json(config.OUTPUT_DIR / "combined_findings.json", aggregate)
    render_multi_account_report(combined_findings_path, config.OUTPUT_DIR / "MULTI_ACCOUNT_REPORT.html")

    return aggregate
