"""Multi-account orchestration: Management Account -> selected accounts -> combined findings.

Wires together src/aws/auth.py's assume_role, src/aws/organizations_collector.py,
and src/main.py's run_pipeline — none of which change here. This module adds
no new AWS permission, no new collector, and no cross-account security
correlation: it only assumes a role per target account, runs the existing,
unmodified audit pipeline once per account, and combines the results.

Discovery via Organizations confirms/reports what's in the org; it does not
choose which accounts get audited by itself. audit_all_accounts() accepts an
explicit target_accounts mapping (label -> account_id) from its caller — the
Streamlit UI builds this from accounts the person actually selected out of
Organizations discovery (see app.py). TARGET_ACCOUNTS below is kept only as
the default for callers that don't supply one (e.g. any direct/CLI use of
this module), so existing behavior is unchanged when no selection is given.
"""

import json
from pathlib import Path

from src import config
from src.aws import auth, organizations_collector
from src.main import TOTAL_PIPELINE_STAGES, run_pipeline
from src.report.multi_account import render_multi_account_report
from src.util.io import write_json
from src.util.status import CollectionStatus

TARGET_ACCOUNTS = {
    "PROD": "328865868092",
    "DEV": "587762853586",
}
ROLE_NAME = "AuditReadOnlyRole"


def discover_accounts(base_session) -> tuple[list[dict], CollectionStatus]:
    """Fetch the accounts visible to this Management Account session, for a
    caller (the UI) that needs to show them and let a person choose which to
    audit, before any audit runs. Thin reuse of organizations_collector — no
    second/different discovery mechanism, no filtering or judgment here.

    A caller that gets a result from this function and then calls
    audit_all_accounts() should pass this same status via that function's
    organizations_status= argument, so Organizations isn't queried twice for
    one audit run.
    """
    data, status = organizations_collector.collect(base_session)
    return data.get("accounts", []), status


def audit_account(base_session, label: str, account_id: str, progress_callback=None) -> dict:
    """Assume the role in one account, run the existing pipeline, never raise.

    A failure here — at authentication or during collection — is returned
    as a result record, not an exception, so one account's problem can
    never stop the other account from being audited.

    progress_callback, if given, is forwarded unchanged to run_pipeline —
    additive only, this function's own behavior/return shape is unaffected.
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
        pipeline_result = run_pipeline(
            target_session,
            identity,
            config.account_output_root(label),
            progress_callback=_with_account_label(progress_callback, label),
        )
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


def _with_account_label(progress_callback, label: str):
    """Wrap a caller-supplied progress_callback so every stage event it
    forwards to run_pipeline also carries which account it's for — without
    run_pipeline itself needing to know about accounts at all."""
    if progress_callback is None:
        return None

    def _wrapped(stage_number, total_stages, stage_name, status, duration_seconds=None):
        progress_callback(
            stage_number, total_stages, stage_name, status=status, duration_seconds=duration_seconds, account_label=label
        )

    return _wrapped


def _tag_findings(findings_path: Path, account_id: str, account_name: str) -> list[dict]:
    """Read one account's untouched findings.json and return tagged copies.

    Does not modify findings_path on disk. Each returned dict is the
    original finding's fields (principal, policy_id, attribution, rule,
    detail) plus account_id/account_name added on top.
    """
    original_findings = json.loads(Path(findings_path).read_text())
    return [{**finding, "account_id": account_id, "account_name": account_name} for finding in original_findings]


def audit_all_accounts(
    base_session,
    target_accounts: dict[str, str] | None = None,
    organizations_status: CollectionStatus | None = None,
    progress_callback=None,
) -> dict:
    """Audit target_accounts (label -> account_id), defaulting to TARGET_ACCOUNTS
    when none is given, so existing callers that don't pick accounts explicitly
    keep their exact prior behavior.

    organizations_status, if given, is used as-is instead of calling
    organizations_collector.collect() again — for a caller (the UI) that
    already discovered accounts via discover_accounts() before this call and
    would otherwise trigger a second, redundant Organizations API call.

    progress_callback, if given, additionally receives one account-transition
    event per account (stage_number=None, account_label=<label>) right before
    that account's own stage events start arriving — the same callback then
    also receives every stage event for that account, tagged with its label.
    """
    if organizations_status is None:
        _discovered, organizations_status = organizations_collector.collect(base_session)

    accounts_to_audit = TARGET_ACCOUNTS if target_accounts is None else target_accounts

    results = []
    for label, account_id in accounts_to_audit.items():
        if progress_callback is not None:
            progress_callback(None, TOTAL_PIPELINE_STAGES, f"Auditing {label}", status="running", account_label=label)
        results.append(audit_account(base_session, label, account_id, progress_callback=progress_callback))

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
