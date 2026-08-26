"""Sentinel — local Streamlit UI.

Replaces "run a long Python command" with a browser form: paste temporary
AWS Management Account credentials, discover the accounts in the
organization, select which ones to audit, then see the dashboard. This file
only wires the UI to the existing, unmodified backend — auth.verify_identity
and src.orchestrator.discover_accounts/audit_all_accounts do all the real
work, exactly as they already do for the CLI path (src/main.py). The
dashboard itself is the primary Sentinel experience: no file:// links, no
raw JSON, no giant tables — everything renders inside Streamlit, reusing
the existing graph/report artifacts that src.main.run_pipeline already
writes to output/<ACCOUNT>/.

Credentials never leave this process: they exist only as local variables
long enough to build one in-memory boto3.Session, are never printed,
logged, or written to any file, and are never part of the aggregate/report
data that does get written (src/orchestrator.py's output already contains
no session/credential material — this file adds nothing that would change
that).
"""

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st

from src import config, orchestrator
from src.aws import auth
from src.report.multi_account import (
    _escalation_chain,
    _findings_for_account,
    _key_risk_groups,
    _risk_counts,
    _risk_level,
)

GET_CREDENTIALS_DURATION_SECONDS = 3600

# =====================================================================
# LOCAL POC ONLY — remove this whole block (and its one call site below)
# before any customer/Aetherion deployment. Prints the temporary
# credentials AWS actually returned to the developer's own terminal, so
# they can manually diff those values against what the masked Streamlit
# fields show. Never used for anything but this one local verification
# step; never touches a file, a report, combined_findings.json, or any
# exception message. Read from an env var (not a bare constant) so the
# test suite can reliably disable it — Streamlit's AppTest re-executes
# this file fresh per run, so a plain module-level flag patched in a test
# would not actually reach that fresh execution; an env var, being real
# process state, does.
# =====================================================================
LOCAL_POC_PRINT_RETRIEVED_CREDENTIALS = os.environ.get("SENTINEL_DISABLE_LOCAL_CREDENTIAL_PRINT") != "1"


class CredentialRetrievalError(Exception):
    """A local-CLI credential retrieval attempt failed, with a message safe to show the user."""


def get_temporary_credentials_via_local_cli(profile: str | None, duration_seconds: int = GET_CREDENTIALS_DURATION_SECONDS) -> dict:
    """Local POC convenience only: use the developer's own `aws` CLI
    configuration — the same credential chain src.aws.auth.get_session's
    profile-based path already relies on — to obtain genuinely temporary
    credentials via STS GetSessionToken, so they don't have to run the
    command by hand and copy-paste the result.

    No browser automation, no console scraping, no password of any kind —
    this only ever shells out to `aws sts get-session-token`, which itself
    only uses whatever the developer's machine is already authenticated
    with locally. Never prints or logs the command's output, on success or
    failure, since a successful run's stdout contains the credentials
    themselves.
    """
    command = ["aws", "sts", "get-session-token", "--duration-seconds", str(duration_seconds), "--output", "json"]
    if profile:
        command += ["--profile", profile]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except FileNotFoundError as exc:
        raise CredentialRetrievalError(
            "AWS CLI not found. Install the AWS CLI, or use 'Paste Temporary Credentials' instead."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CredentialRetrievalError(
            "Timed out waiting for the AWS CLI. Check your local AWS configuration."
        ) from exc

    if result.returncode != 0:
        # Never surface result.stderr verbatim — it can echo back parts of
        # the attempted command/config. A short, generic message is enough
        # for a local dev tool; the developer can always run the same `aws`
        # command by hand to see the real error if they need to debug it.
        raise CredentialRetrievalError(
            "Could not obtain temporary credentials from your local AWS CLI configuration. "
            "Make sure you're authenticated locally (e.g. `aws sts get-caller-identity` succeeds) and try again."
        )

    try:
        credentials = json.loads(result.stdout)["Credentials"]
        parsed = {
            "access_key_id": credentials["AccessKeyId"],
            "secret_access_key": credentials["SecretAccessKey"],
            "session_token": credentials["SessionToken"],
            "expiration": credentials.get("Expiration"),
        }
    except (json.JSONDecodeError, KeyError) as exc:
        raise CredentialRetrievalError("Unexpected response from the AWS CLI.") from exc

    _print_credentials_local_poc_only(parsed)
    return parsed


def _print_credentials_local_poc_only(credentials: dict) -> None:
    """LOCAL POC ONLY — see the module-level flag above. Prints exactly the
    four parsed fields (never the raw AWS CLI stdout blob, which could
    contain unrelated output) so a developer can visually compare these
    against the masked values shown in Streamlit. Delete this function and
    its one call site above before any customer/Aetherion deployment."""
    if not LOCAL_POC_PRINT_RETRIEVED_CREDENTIALS:
        return
    print()
    print("Temporary AWS credentials retrieved:")
    print()
    print(f"Access Key ID: {credentials['access_key_id']}")
    print(f"Secret Access Key: {credentials['secret_access_key']}")
    print(f"Session Token: {credentials['session_token']}")
    print(f"Expiration: {credentials.get('expiration')}")
    print()


# Credentials expiring within this many seconds are treated as no longer
# valid — avoids the UI calling STS again, then a click/rerun later, using a
# session that's already about to be rejected by AWS. Deliberately small:
# just enough to absorb the gap between a validity check and the user's
# next action, not a stand-in for the real expiration AWS returned.
_CREDENTIAL_EXPIRATION_SAFETY_BUFFER_SECONDS = 60


def _parse_expiration(expiration) -> datetime | None:
    """Parse the Expiration STS actually returned. Returns None (never
    raises) on anything unparseable, so callers can fail closed — treat
    unparseable/missing expiration as NOT valid, never as valid."""
    if not expiration:
        return None
    try:
        parsed = datetime.fromisoformat(str(expiration).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _credentials_still_valid(expiration) -> bool:
    parsed = _parse_expiration(expiration)
    if parsed is None:
        return False
    return parsed > datetime.now(timezone.utc) + timedelta(seconds=_CREDENTIAL_EXPIRATION_SAFETY_BUFFER_SECONDS)


def _remaining_validity_text(expiration) -> str:
    parsed = _parse_expiration(expiration)
    if parsed is None:
        return "-"
    remaining_seconds = (parsed - datetime.now(timezone.utc)).total_seconds()
    if remaining_seconds <= 0:
        return "0s"
    return _format_elapsed(remaining_seconds)


def build_session(
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    region_name: str,
) -> boto3.Session:
    """Build an in-memory boto3.Session from supplied temporary credentials.

    Never writes anything to disk — this is exactly the "raw credentials as
    Session parameters" mechanism boto3 documents, used here instead of
    src.aws.auth.get_session's profile-based path because the UI's input is
    pasted temporary credentials, not a local named profile.
    """
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token or None,
        region_name=region_name,
    )


def summarize_accounts(aggregate: dict) -> list[dict]:
    """Pure, testable projection of aggregate['accounts'] for display."""
    summaries = []
    for account in aggregate.get("accounts", []):
        summaries.append(
            {
                "label": account.get("account_label", "?"),
                "id": account.get("account_id", "?"),
                "status": account.get("status", "unknown"),
                "finding_count": account.get("finding_count", 0),
                "failure_stage": account.get("failure_stage"),
                "error": account.get("error"),
            }
        )
    return summaries


def format_auth_error() -> str:
    return "Unable to authenticate with AWS. Check the supplied credentials."


def format_audit_error(exc: Exception) -> str:
    return f"Audit failed: {exc}"


# --- small pure helpers over an aggregate, used by several tabs ------------


def _account_record(aggregate: dict, label: str) -> dict | None:
    for account in aggregate.get("accounts", []):
        if account.get("account_label") == label:
            return account
    return None


def _account_findings(aggregate: dict, label: str) -> list[dict]:
    account = _account_record(aggregate, label)
    if not account:
        return []
    return _findings_for_account(aggregate.get("findings", []), account.get("account_id"))


def _rule_display_name(rule: str) -> str:
    return rule.replace("_", " ").title()


def _account_status_label(high: int, review: int) -> str:
    if high > 0:
        return "Needs Attention"
    if review > 0:
        return "Review Recommended"
    return "Clean"


def _overall_status(aggregate: dict) -> tuple[str, int, int]:
    findings = aggregate.get("findings", [])
    high, review = _risk_counts(findings)
    return _account_status_label(high, review), high, review


def _executive_summary(aggregate: dict) -> str:
    """One plain-language sentence, derived entirely from this run's real
    findings — never a fixed template string. Findings (scanner results)
    and priority security concerns (the curated, deduplicated scenarios
    from _key_risk_groups) are counted and named separately, so a single
    underlying scenario that produced several findings is never described
    as several separate issues. Leads with whichever curated concern is
    most significant: an escalation path first, then any other high-risk
    item, else nothing extra to lead with.
    """
    accounts = aggregate.get("accounts", [])
    findings = aggregate.get("findings", [])
    high, review = _risk_counts(findings)
    key_risks = _key_risk_groups(findings)
    account_count = len(accounts)

    summary = (
        f"{account_count} AWS account{'s' if account_count != 1 else ''} were audited. "
        f"Sentinel found {high} high-risk finding{'s' if high != 1 else ''} and "
        f"{review} access-review finding{'s' if review != 1 else ''}"
    )
    if key_risks:
        summary += f", covering {len(key_risks)} priority security concern{'s' if len(key_risks) != 1 else ''}."
    else:
        summary += "."

    if not key_risks:
        return summary

    top = key_risks[0]
    principal_name = top.get("principal", {}).get("name", "?")
    if top.get("rule") == "indirect_privilege_path":
        chain = _escalation_chain(top.get("detail", ""))
        if chain:
            summary += f" The most significant issue is an indirect path from {chain[0]} to administrative access."
            return summary

    category = _risk_category(top)
    summary += f" The most significant issue is {principal_name}'s {category.lower()}."
    return summary


# --- rendering: compact account summaries + key-risk cards -----------------


def _account_summary_card(aggregate: dict, label: str) -> None:
    """One compact card: name, finding/high/review counts, status word. No
    findings, no key risks here — that's Findings' and Overview's job."""
    account = _account_record(aggregate, label)
    if not account:
        return
    st.markdown(f"**{label}**")
    st.caption(f"Account ID: {account.get('account_id', '?')}")
    if account.get("status") != "success":
        st.error(f"Audit failed ({account.get('failure_stage', '?')})")
        return

    findings = _account_findings(aggregate, label)
    high, review = _risk_counts(findings)
    status_icon = "🔴" if high > 0 else ("🟡" if review > 0 else "🟢")
    st.markdown(f"{status_icon} **{_account_status_label(high, review)}**")
    st.metric("Findings", len(findings))
    col1, col2 = st.columns(2)
    col1.markdown(f"🔴 **{high}** High Risk")
    col2.markdown(f"🟡 **{review}** Review")


def _key_risk_one_liner(finding: dict) -> tuple[str, str]:
    """(header, detail) pair for a compact one-line-plus-detail concern —
    used by the Accounts tab, never the full card (that's Overview's job)."""
    level = _risk_level(finding.get("rule", ""))
    badge = "🔴" if level == "HIGH RISK" else "🟡"
    category = _risk_category(finding)
    chain = _escalation_chain(finding.get("detail", "")) if finding.get("rule") == "indirect_privilege_path" else None
    detail = " → ".join(chain) if chain else finding.get("principal", {}).get("name", "?")
    return f"{badge} {category}", detail


_RISK_CATEGORY_LABELS = {
    "indirect_privilege_path": "Privilege Escalation",
    "administrative_access": "Administrative Access",
    "broad_permission": "Administrative Access",
    "potentially_unused_access": "Unused Access",
}


def _risk_category(finding: dict) -> str:
    """Presentation-only label mapping — same rule, friendlier category name.
    Never changes which rule fired or how it was classified as HIGH RISK/REVIEW."""
    return _RISK_CATEGORY_LABELS.get(finding.get("rule", ""), _rule_display_name(finding.get("rule", "-")))


# Plain-language templates keyed on the existing, fixed rule set that
# _KEY_RISK_SPEC already curates (indirect_privilege_path /
# administrative_access / broad_permission / potentially_unused_access).
# These reword the same underlying fact for a non-technical reader — they
# never add a fact the rule/detail didn't already establish.


def _plain_what_we_found(finding: dict, chain: list[str] | None) -> str:
    principal = finding.get("principal", {}).get("name", "?")
    rule = finding.get("rule")
    if rule == "indirect_privilege_path" and chain:
        return f"{chain[0]} can potentially move from a developer role into an administrative role."
    if rule in ("administrative_access", "broad_permission"):
        return f"{principal} has unrestricted AWS permissions."
    if rule == "potentially_unused_access":
        return f"No recent usage was observed for {principal}'s access in the available evidence."
    return finding.get("detail", "-")


def _plain_why_it_matters(finding: dict) -> str:
    rule = finding.get("rule")
    if rule == "indirect_privilege_path":
        return "If this identity were compromised, an attacker could potentially reach unrestricted AWS permissions."
    if rule in ("administrative_access", "broad_permission"):
        return "Unrestricted access means a mistake or a compromised credential here could affect the entire AWS account."
    if rule == "potentially_unused_access":
        return "Access that isn't being used still expands what an attacker could do if this identity were ever compromised."
    return finding.get("detail", "-")


def _recommended_action(finding: dict) -> str:
    rule = finding.get("rule")
    if rule == "indirect_privilege_path":
        return "Review the role-assumption path and remove any unnecessary access."
    if rule in ("administrative_access", "broad_permission"):
        return "Scope this permission down to only what is required."
    if rule == "potentially_unused_access":
        return "Confirm whether this access is still needed, and remove it if not."
    return "Review this finding."


def _render_chain_visual(chain: list[str]) -> None:
    """Lightweight vertical path — not the interactive graph, just enough to
    show the shape of an escalation without redrawing the Graph tab."""
    steps = [*chain, "Administrative Access"]
    st.markdown("  \n⬇  \n".join(f"**{step}**" for step in steps))


def _key_risk_card(finding: dict) -> None:
    """Overview's main content: one plain-language security story per
    curated risk — what we found / why it matters / recommended action —
    with every technical fact (policy ID, attribution, raw rule name, raw
    detail) moved behind an expander rather than shown by default."""
    level = _risk_level(finding.get("rule", ""))
    badge = "🔴" if level == "HIGH RISK" else "🟡"
    category = _risk_category(finding)
    chain = _escalation_chain(finding.get("detail", "")) if finding.get("rule") == "indirect_privilege_path" else None

    with st.container(border=True):
        st.markdown(f"{badge} **{finding.get('account_name', '?')} · {category}**")

        if chain:
            _render_chain_visual(chain)

        st.markdown("**What we found**")
        st.write(_plain_what_we_found(finding, chain))

        st.markdown("**Why it matters**")
        st.write(_plain_why_it_matters(finding))

        st.markdown("**Recommended action**")
        st.write(_recommended_action(finding))

        with st.expander("View technical details"):
            attribution = finding.get("attribution") or {}
            st.caption(f"Rule: {finding.get('rule_display', finding.get('rule', '-'))}")
            st.caption(f"Principal: {finding.get('principal', {}).get('name', '-')}")
            st.caption(f"Policy ID: {finding.get('policy_id', '-')}")
            st.caption(f"Attribution: {attribution.get('attachment_type', '-')}")
            st.write(finding.get("detail", "-"))


def _finding_card(finding: dict) -> None:
    level = _risk_level(finding.get("rule", ""))
    badge = "🔴 HIGH RISK" if level == "HIGH RISK" else "🟡 REVIEW"
    principal = finding.get("principal", {})

    with st.container(border=True):
        st.markdown(f"**{finding.get('account_name', '?')}**  ·  {badge}")
        st.markdown(f"{principal.get('name', '-')} — {_rule_display_name(finding.get('rule', '-'))}")

        with st.expander("View details"):
            st.write(finding.get("detail", "-"))
            attribution = finding.get("attribution") or {}
            st.caption(f"Policy ID: {finding.get('policy_id', '-')}")
            st.caption(f"Attribution: {attribution.get('attachment_type', '-')}")


# --- rendering: embedding/downloading existing HTML artifacts, no file:// --

# pyvis's generated graph.html references its vis.js/vis.min.css assets via
# a relative path (../node_modules/vis/dist/...) that assumes a local
# node_modules folder next to the file — one was never generated, so that
# path is dead on disk regardless of how the file is opened. Embedding via
# st.iframe (an HTML string, not a URL/path) renders the file inside an
# iframe with no real base URL at all, which can't resolve any relative path
# either way. This patches only the two known-broken asset references to
# their CDN equivalents (same vis.js 4.x API the generated file already
# calls — vis.Network/vis.DataSet) at render time, in memory, right before
# embedding. It never edits the file on disk and never touches
# src/graph/visualize.py — the artifact itself, and how it's generated,
# are both untouched.
_VIS_ASSET_FIXES = {
    '../node_modules/vis/dist/vis.js': 'https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js',
    '../node_modules/vis/dist/vis.min.css': 'https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css',
}


def _patch_graph_html_assets(html_text: str) -> str:
    for broken_relative_path, cdn_url in _VIS_ASSET_FIXES.items():
        html_text = html_text.replace(broken_relative_path, cdn_url)
    return html_text


def _embed_html_file(path, height: int = 650, patch_vis_assets: bool = False) -> bool:
    """Embed an existing HTML artifact inline. Returns False if it doesn't exist yet.

    st.iframe embeds an HTML string exactly like the deprecated
    st.components.v1.html did (same srcdoc-style iframe, JS execution
    included — required for vis.js to render the graph); the only
    difference is scrollbar control, where st.iframe has no explicit
    scrolling flag and instead always uses the browser's own default
    ("auto": a scrollbar appears only if the content overflows the fixed
    height), rather than components.html's forced scrolling=True.
    """
    if not path.exists():
        return False
    html_text = path.read_text(encoding="utf-8")
    if patch_vis_assets:
        html_text = _patch_graph_html_assets(html_text)
    st.iframe(html_text, height=height)
    return True


def _download_button_for(path, label: str, key: str) -> None:
    if not path.exists():
        st.info(f"{label} is not available yet.")
        return
    st.download_button(label, data=path.read_bytes(), file_name=path.name, mime="text/html", key=key)


def _render_relationship_graph(label: str) -> None:
    """Graph tab's one job: how identities/roles/policies connect for one
    account. No findings, no account cards, no report download here — just
    the graph, what it means, and a way to get the file."""
    st.write(
        "This graph shows how users, groups, roles, and policies in "
        f"**{label}** are connected — including which roles can be assumed "
        "and which policies grant access."
    )
    graph_file = config.graph_dir(label) / "graph.html"
    embedded = _embed_html_file(graph_file, patch_vis_assets=True)
    if not embedded:
        st.info("Graph not available yet for this account.")
    _download_button_for(graph_file, f"Download {label} Graph", key=f"dl_graph_{label}")


# --- tabs --------------------------------------------------------------


def _render_overview(aggregate: dict) -> None:
    """Answers exactly one question: what is wrong with this environment?
    Status + counts + one derived sentence + the curated key risks + which
    accounts they're in. No per-finding technical detail lives here — that's
    Findings' job."""
    findings = aggregate.get("findings", [])
    status_label, high, review = _overall_status(aggregate)
    status_icon = "🔴" if high > 0 else ("🟡" if review > 0 else "🟢")

    st.subheader(f"{status_icon} {status_label}")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Accounts Audited", len(aggregate.get("accounts", [])))
    col2.metric("Total Findings", len(findings))
    col3.metric("High Risk", high)
    col4.metric("Review", review)

    st.write(_executive_summary(aggregate))

    st.subheader("Key Security Risks")
    key_risks = _key_risk_groups(findings)
    if not key_risks:
        st.info("No key risks identified.")
    for finding in key_risks:
        _key_risk_card(finding)

    st.subheader("Affected Accounts")
    for account in aggregate.get("accounts", []):
        label = account.get("account_label", "?")
        if account.get("status") != "success":
            st.markdown(f"**{label}** — audit failed ({account.get('failure_stage', '?')})")
            continue
        account_findings = _account_findings(aggregate, label)
        acc_high, acc_review = _risk_counts(account_findings)
        acc_icon = "🔴" if acc_high > 0 else ("🟡" if acc_review > 0 else "🟢")
        st.markdown(
            f"**{label}** — {len(account_findings)} findings · {acc_high} high-risk  "
            f"{acc_icon} {_account_status_label(acc_high, acc_review)}"
        )


def _render_findings(aggregate: dict) -> None:
    """Answers: what exactly did Sentinel detect? The investigation view —
    every finding, filterable, technical detail one click away."""
    findings = aggregate.get("findings", [])
    st.subheader(f"All Findings ({len(findings)})")
    if not findings:
        st.info("No findings.")
        return

    account_options = ["All"] + sorted({f.get("account_name", "?") for f in findings})
    rule_options = ["All"] + sorted({f.get("rule", "?") for f in findings})
    col1, col2 = st.columns(2)
    account_filter = col1.selectbox("Account", account_options, key="findings_account_filter")
    rule_filter = col2.selectbox("Rule", rule_options, key="findings_rule_filter")

    filtered = findings
    if account_filter != "All":
        filtered = [f for f in filtered if f.get("account_name") == account_filter]
    if rule_filter != "All":
        filtered = [f for f in filtered if f.get("rule") == rule_filter]

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
    for finding in filtered:
        _finding_card(finding)


def _render_accounts(aggregate: dict) -> None:
    """Answers: which accounts have problems? Compact per-account summaries
    up top, then a selector with just enough detail (counts + top issues)
    plus a link to the existing detailed report — never the full finding
    list, that's Findings' job."""
    accounts = aggregate.get("accounts", [])
    if not accounts:
        st.info("No accounts audited.")
        return

    labels = [a.get("account_label", "?") for a in accounts]
    columns = st.columns(len(labels) or 1)
    for column, label in zip(columns, labels):
        with column, st.container(border=True):
            _account_summary_card(aggregate, label)

    st.divider()
    selected = st.selectbox("Select an account for details", labels, key="accounts_tab_select")
    account = _account_record(aggregate, selected)
    if not account:
        return

    st.markdown(f"### {selected}")
    st.caption(f"Account ID: {account.get('account_id', '?')}")
    if account.get("status") != "success":
        st.error(f"{account.get('failure_stage', '?')}: {account.get('error', '')}")
        return

    findings = _account_findings(aggregate, selected)
    high, review = _risk_counts(findings)
    col1, col2, col3 = st.columns(3)
    col1.metric("Findings", len(findings))
    col2.metric("High Risk", high)
    col3.metric("Review", review)
    st.caption(f"Status: {_account_status_label(high, review)}")

    account_key_risks = [f for f in _key_risk_groups(aggregate.get("findings", [])) if f.get("account_name") == selected]
    if account_key_risks:
        st.markdown("**Top issues**")
        for finding in account_key_risks[:3]:
            header, detail = _key_risk_one_liner(finding)
            st.markdown(header)
            st.caption(detail)

    st.divider()
    st.caption("Full technical detail, evidence, and the security graph for this account:")
    _download_button_for(config.report_path(selected), f"Download Full {selected} Report", key=f"dl_report_{selected}")


def _render_graph(aggregate: dict) -> None:
    """Answers: how are these identities, roles, policies and permissions
    connected? Nothing else — no findings list, no account cards."""
    successful = [a for a in aggregate.get("accounts", []) if a.get("status") == "success"]
    if not successful:
        st.info("No successfully audited accounts to show a graph for.")
        return

    labels = [a.get("account_label", "?") for a in successful]
    selected = st.selectbox("Account", labels, key="graph_tab_select")
    _render_relationship_graph(selected)


def render_dashboard(aggregate: dict) -> None:
    st.header("Sentinel")
    st.caption("Multi-Account IAM Security Audit")

    organizations_status = aggregate.get("organizations_status") or {}
    if not organizations_status.get("succeeded", True):
        st.warning(
            "AWS Organizations discovery did not succeed "
            f"({organizations_status.get('error', 'unknown error')}). "
            "PROD and DEV were still audited directly using the configured target accounts."
        )

    overview_tab, findings_tab, accounts_tab, graph_tab = st.tabs(["Overview", "Findings", "Accounts", "Graph"])
    with overview_tab:
        _render_overview(aggregate)
    with findings_tab:
        _render_findings(aggregate)
    with accounts_tab:
        _render_accounts(aggregate)
    with graph_tab:
        _render_graph(aggregate)


# --- real stage-by-stage progress (wires run_pipeline's/orchestrator's -----
# --- progress_callback into a live Streamlit checklist, no print parsing) --

# Mirrors the real order src.main.run_pipeline actually fires its stages in
# (stage 6 genuinely runs after 7 and 8 — see that module's own comments on
# why) — not a re-sorted/invented order. Kept here rather than imported so
# this file's only dependency on src.main stays the progress_callback
# contract itself, not its internal stage bookkeeping.
PIPELINE_STAGE_ORDER = [
    (2, "IAM Configuration Collection"),
    (3, "IAM Normalization"),
    (4, "Group Inheritance"),
    (5, "Last Accessed Evidence"),
    (7, "Relationship Graph"),
    (8, "CloudTrail Event History"),
    (6, "Deterministic Security Analysis"),
    (9, "Access Analyzer & Evidence Package"),
    (10, "AI Security Explanation"),
]

_STAGE_ICONS = {"completed": "✓", "failed": "✗", "running": "●"}


def _format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs}s"


def _make_progress_renderer(placeholder, audit_started_at: float):
    """Returns a progress_callback closure that redraws `placeholder` on every
    stage/account event. Stage checklist is fixed (PIPELINE_STAGE_ORDER);
    only each entry's ✓/●/○/✗ + duration changes as real events arrive.
    """
    stage_status: dict[int, dict] = {}
    current_account: dict[str, str | None] = {"label": None}

    def _render() -> None:
        elapsed = time.perf_counter() - audit_started_at
        completed_or_failed = sum(1 for s in stage_status.values() if s["status"] in ("completed", "failed"))
        running = any(s["status"] == "running" for s in stage_status.values())
        step_position = completed_or_failed + (1 if running else 0)

        lines = ["**Security Audit**", ""]
        if current_account["label"]:
            lines.append(f"**Auditing {current_account['label']}**")
        lines.append(f"Step {step_position} of {len(PIPELINE_STAGE_ORDER)}")
        lines.append("")
        for number, name in PIPELINE_STAGE_ORDER:
            info = stage_status.get(number)
            icon = _STAGE_ICONS.get(info["status"], "○") if info else "○"
            duration_text = ""
            if info and info["status"] in ("completed", "failed") and info.get("duration_seconds") is not None:
                duration_text = f"   {info['duration_seconds']:.2f}s"
            lines.append(f"{icon} {name}{duration_text}")
        lines.append("")
        lines.append(f"Elapsed time: {_format_elapsed(elapsed)}")
        placeholder.markdown("\n\n".join(lines))

    def _progress_callback(stage_number, total_stages, stage_name, status, duration_seconds=None, account_label=None):
        if account_label is not None and account_label != current_account["label"]:
            current_account["label"] = account_label
            stage_status.clear()
        if stage_number is not None:
            stage_status[stage_number] = {"status": status, "duration_seconds": duration_seconds}
        _render()

    _render()
    return _progress_callback


def _retrieve_and_store_credentials() -> None:
    """One STS call, stored into session state. Never touches the audit —
    callers are exactly the three credential buttons in main(), none of
    which also trigger Connect & Audit."""
    st.session_state["credential_retrieval_error"] = None
    st.session_state["credentials_retrieved"] = False
    try:
        credentials = get_temporary_credentials_via_local_cli(config.AWS_PROFILE_NAME)
        st.session_state["access_key_id"] = credentials["access_key_id"]
        st.session_state["secret_access_key"] = credentials["secret_access_key"]
        st.session_state["session_token"] = credentials["session_token"]
        st.session_state["credential_expiration"] = credentials.get("expiration")
        st.session_state["credentials_retrieved"] = True
    except CredentialRetrievalError as exc:
        st.session_state["credential_retrieval_error"] = str(exc)


def _account_checkbox_label(account: dict) -> str:
    return f"{account.get('name', '?')} — {account.get('id', '?')} ({account.get('state', '?')})"


def _selected_target_accounts(discovered_accounts: list[dict]) -> dict[str, str]:
    """Build the label -> account_id mapping audit_all_accounts expects, from
    whichever discovered accounts have their checkbox checked. Two accounts
    sharing the same name would otherwise collide as dict keys and silently
    drop one of them, so a colliding label is disambiguated with its account
    ID rather than allowed to overwrite another selected account.
    """
    selected = [a for a in discovered_accounts if st.session_state.get(f"select_account_{a['id']}")]
    names = [a.get("name") or a["id"] for a in selected]
    target_accounts: dict[str, str] = {}
    for account, name in zip(selected, names):
        label = name if names.count(name) == 1 else f"{name} ({account['id']})"
        target_accounts[label] = account["id"]
    return target_accounts


def main() -> None:
    st.set_page_config(page_title="Sentinel", layout="wide")
    st.title("Sentinel")
    st.caption("Multi-Account IAM Security Audit")

    st.session_state.setdefault("aggregate", None)
    st.session_state.setdefault("error", None)
    st.session_state.setdefault("access_key_id", "")
    st.session_state.setdefault("secret_access_key", "")
    st.session_state.setdefault("session_token", "")
    st.session_state.setdefault("region", "us-east-1")
    st.session_state.setdefault("credential_retrieval_error", None)
    st.session_state.setdefault("credentials_retrieved", False)
    st.session_state.setdefault("credential_expiration", None)
    st.session_state.setdefault("discovered_accounts", None)
    st.session_state.setdefault("organizations_status", None)
    st.session_state.setdefault("discovery_error", None)

    st.subheader("Connect AWS")
    st.caption("Choose how to connect:")
    mode = st.radio(
        "Connection method",
        ["Paste Temporary Credentials", "Get Temporary Credentials"],
        label_visibility="collapsed",
        key="connection_mode",
    )

    if mode == "Paste Temporary Credentials":
        st.text_input("AWS Access Key ID", key="access_key_id")
        st.text_input("AWS Secret Access Key", type="password", key="secret_access_key")
        st.text_input("AWS Session Token", type="password", key="session_token")
        st.text_input("AWS Region", key="region")
    else:
        st.write("Use your local AWS authentication to obtain temporary credentials automatically.")
        st.text_input("AWS Region", key="region")

        existing_expiration = st.session_state.get("credential_expiration")
        has_prior_credentials = bool(st.session_state.get("credentials_retrieved"))
        still_valid = has_prior_credentials and _credentials_still_valid(existing_expiration)

        if still_valid:
            st.success("Temporary credentials already available")
            st.caption(f"Expires: {existing_expiration}")
            st.caption(f"Valid for: {_remaining_validity_text(existing_expiration)}")
            if st.button("Generate New Credentials"):
                _retrieve_and_store_credentials()
        else:
            if has_prior_credentials:
                st.info("Temporary credentials expired")
            if st.button("Get Temporary Credentials"):
                _retrieve_and_store_credentials()

        if st.session_state.get("credential_retrieval_error"):
            st.error(st.session_state["credential_retrieval_error"])
        elif st.session_state.get("credentials_retrieved"):
            reveal = st.checkbox("👁 Show credentials")
            field_type = "default" if reveal else "password"
            st.text_input("Access Key ID", type=field_type, key="access_key_id", disabled=True)
            st.text_input("Secret Access Key", type=field_type, key="secret_access_key", disabled=True)
            st.text_input("Session Token", type=field_type, key="session_token", disabled=True)
            st.caption(f"Expiration: {st.session_state.get('credential_expiration') or '-'}")

    discover_clicked = st.button("Connect & Discover Accounts", type="primary")

    if discover_clicked:
        st.session_state["error"] = None
        st.session_state["discovery_error"] = None
        st.session_state["aggregate"] = None
        st.session_state["discovered_accounts"] = None
        st.session_state["organizations_status"] = None

        with st.status("Connecting to AWS...", expanded=True) as status:
            try:
                session = build_session(
                    st.session_state["access_key_id"],
                    st.session_state["secret_access_key"],
                    st.session_state["session_token"],
                    st.session_state["region"],
                )

                status.write("Verifying Management Account...")
                identity = auth.verify_identity(session)
                status.write(f"Verified Management Account: {identity['account_id']}")

                status.write("Discovering AWS accounts...")
                discovered_accounts, organizations_status = orchestrator.discover_accounts(session)
                st.session_state["discovered_accounts"] = discovered_accounts
                st.session_state["organizations_status"] = organizations_status

                if not organizations_status.succeeded:
                    st.session_state["discovery_error"] = (
                        f"Account discovery did not succeed ({organizations_status.error}). "
                        "No accounts are available to select."
                    )
                    status.update(label="Discovery failed", state="error")
                elif not discovered_accounts:
                    st.session_state["discovery_error"] = "No accounts were discovered for this Management Account."
                    status.update(label="No accounts found", state="error")
                else:
                    status.update(label=f"Discovered {len(discovered_accounts)} account(s)", state="complete", expanded=False)
            except auth.AuthError:
                status.update(label="Authentication failed", state="error")
                st.session_state["error"] = format_auth_error()
            except Exception as exc:  # noqa: BLE001 — surfaced as a clean message, not a raw traceback
                status.update(label="Discovery failed", state="error")
                st.session_state["error"] = format_audit_error(exc)

    discovered_accounts = st.session_state.get("discovered_accounts")
    if discovered_accounts:
        st.subheader("Select accounts to audit")
        st.caption("Discovered via AWS Organizations. Nothing is audited until you select accounts and run the audit.")
        for account in discovered_accounts:
            st.checkbox(_account_checkbox_label(account), key=f"select_account_{account['id']}", value=False)

        run_clicked = st.button("Run Audit", type="primary")

        if run_clicked:
            target_accounts = _selected_target_accounts(discovered_accounts)
            if not target_accounts:
                st.error("Select at least one account before running the audit.")
            else:
                st.session_state["error"] = None
                st.session_state["aggregate"] = None
                audit_started_at = time.perf_counter()

                with st.status("Running audit...", expanded=True) as status:
                    try:
                        session = build_session(
                            st.session_state["access_key_id"],
                            st.session_state["secret_access_key"],
                            st.session_state["session_token"],
                            st.session_state["region"],
                        )
                        progress_placeholder = status.empty()
                        progress_callback = _make_progress_renderer(progress_placeholder, audit_started_at)
                        aggregate = orchestrator.audit_all_accounts(
                            session,
                            target_accounts=target_accounts,
                            organizations_status=st.session_state["organizations_status"],
                            progress_callback=progress_callback,
                        )

                        st.session_state["aggregate"] = aggregate
                        status.update(label="Audit complete", state="complete", expanded=False)
                    except auth.AuthError:
                        status.update(label="Authentication failed", state="error")
                        st.session_state["error"] = format_auth_error()
                    except Exception as exc:  # noqa: BLE001 — surfaced as a clean message, not a raw traceback
                        status.update(label="Audit failed", state="error")
                        st.session_state["error"] = format_audit_error(exc)

                if st.session_state.get("aggregate"):
                    completed = st.session_state["aggregate"]
                    total_elapsed = time.perf_counter() - audit_started_at
                    st.success(
                        "**Audit completed successfully**\n\n"
                        f"{len(completed.get('accounts', []))} accounts audited\n\n"
                        f"{completed.get('total_findings', 0)} findings\n\n"
                        f"{completed.get('accounts_failed', 0)} failures\n\n"
                        f"Total audit time: {_format_elapsed(total_elapsed)}"
                    )
    elif st.session_state.get("discovery_error"):
        st.warning(st.session_state["discovery_error"])

    if st.session_state.get("error"):
        st.error(st.session_state["error"])

    if st.session_state.get("aggregate"):
        render_dashboard(st.session_state["aggregate"])


if __name__ == "__main__":
    main()
