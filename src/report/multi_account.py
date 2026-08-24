"""Combined multi-account HTML report — executive overview, not a JSON viewer.

Reads output/combined_findings.json (already assembled by src/orchestrator.py)
and renders one self-contained HTML page: header stats, a short summary, an
account card per audited account, a curated set of key risks, drill-down
links to each account's own detailed REPORT.html, and every finding still
available (collapsed by default) so the combined report stays complete.

Presentation only — invents nothing, recomputes nothing, never touches a
per-account findings.json or REPORT.html, and never embeds a graph (each
account's own REPORT.html already has its own).

Risk labeling is derived purely from which existing deterministic rule
fired (indirect_privilege_path / administrative_access / broad_permission
= HIGH RISK, potentially_unused_access = REVIEW) — no severity value is
invented or read from anywhere the audit engine doesn't already provide.
"""

import html as html_escape
import json
from pathlib import Path

_ACCOUNT_COLORS = {
    "PROD": "#9a3412",
    "DEV": "#1e40af",
}
_DEFAULT_COLOR = "#52525b"

_HIGH_RISK_RULES = {"indirect_privilege_path", "administrative_access", "broad_permission"}


def _esc(value) -> str:
    return html_escape.escape(str(value), quote=False)


def _account_color(account_label: str) -> str:
    return _ACCOUNT_COLORS.get(account_label, _DEFAULT_COLOR)


def _risk_level(rule: str) -> str:
    return "HIGH RISK" if rule in _HIGH_RISK_RULES else "REVIEW"


def _findings_for_account(findings: list[dict], account_id: str) -> list[dict]:
    return [f for f in findings if f.get("account_id") == account_id]


def _risk_counts(account_findings: list[dict]) -> tuple[int, int]:
    high = sum(1 for f in account_findings if _risk_level(f.get("rule", "")) == "HIGH RISK")
    review = len(account_findings) - high
    return high, review


def _escalation_chain(detail: str) -> list[str] | None:
    """Pull the principal -> role -> role chain out of an indirect_privilege_path detail string.

    That string already reads "A -> B -> C reaches administrative access...";
    this only re-splits it for vertical display, it doesn't add information.
    """
    marker = " reaches administrative access"
    if marker not in detail:
        return None
    prefix = detail.split(marker, 1)[0]
    return [step.strip() for step in prefix.split(" -> ") if step.strip()]


def _attribution_text(attribution: dict | None) -> str:
    if not attribution:
        return "-"
    attachment_type = attribution.get("attachment_type", "-")
    if attachment_type == "group_inherited":
        return f"group_inherited ({_esc(attribution.get('source_group_name', '?'))})"
    return _esc(attachment_type)


def _account_badge(account_label: str, account_id: str | None = None) -> str:
    color = _account_color(account_label)
    id_part = f' <span style="color:#71717a;font-weight:400;">({_esc(account_id)})</span>' if account_id else ""
    return (
        f'<span style="display:inline-block;padding:2px 9px;border-radius:5px;'
        f'background:{color};color:#fff;font-weight:700;font-size:0.78rem;'
        f'letter-spacing:0.03em;">{_esc(account_label)}</span>{id_part}'
    )


def _risk_pill(level: str) -> str:
    color = "#b91c1c" if level == "HIGH RISK" else "#a16207"
    bg = "#fef2f2" if level == "HIGH RISK" else "#fefce8"
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:999px;'
        f'background:{bg};color:{color};font-weight:700;font-size:0.72rem;'
        f'letter-spacing:0.03em;border:1px solid {color}22;">{level}</span>'
    )


def _account_card_html(account: dict, account_findings: list[dict]) -> str:
    label = account.get("account_label", "?")
    account_id = account.get("account_id", "?")
    status = account.get("status", "unknown")

    if status != "success":
        stage = _esc(account.get("failure_stage", "unknown"))
        error = _esc(account.get("error", ""))
        return f"""
        <div style="border:1px solid #e4e4e7;border-left:4px solid #b91c1c;border-radius:8px;
                    padding:1rem 1.25rem;min-width:220px;background:#fff;">
          {_account_badge(label, account_id)}
          <div style="margin-top:0.6rem;color:#b91c1c;font-weight:600;">Audit: Failed ({stage})</div>
          <div style="margin-top:0.3rem;color:#71717a;font-size:0.85rem;">{error}</div>
        </div>"""

    high, review = _risk_counts(account_findings)
    color = _account_color(label)
    return f"""
    <div style="border:1px solid #e4e4e7;border-left:4px solid {color};border-radius:8px;
                padding:1rem 1.25rem;min-width:220px;background:#fff;">
      {_account_badge(label, account_id)}
      <div style="margin-top:0.6rem;color:#15803d;font-weight:600;">Audit: Success</div>
      <div style="margin-top:0.5rem;font-size:1.3rem;font-weight:700;">{_esc(len(account_findings))}
        <span style="font-size:0.85rem;font-weight:400;color:#71717a;">Findings</span></div>
      <div style="margin-top:0.35rem;font-size:0.85rem;">
        <span style="color:#b91c1c;font-weight:600;">{_esc(high)} High Risk</span>
        &nbsp;&middot;&nbsp;
        <span style="color:#a16207;font-weight:600;">{_esc(review)} Review</span>
      </div>
    </div>"""


# The intentional scenarios planted for this POC's multi-account demo —
# (account label, principal name, rule(s) that principal's entry should
# show). Kept as an explicit list rather than a generic "top N risky
# findings" heuristic so the report reliably leads with the scenarios this
# POC was built to demonstrate, not whatever AWS-native noise (the account's
# own OrganizationAccountAccessRole, AWS service-linked roles) happens to
# also match the same rules. That noise still fully appears under
# All Findings — it's excluded only from this curated section.
_KEY_RISK_SPEC = [
    ("PROD", "prod-alice", {"indirect_privilege_path"}),
    ("PROD", "ProdAdminRole", {"broad_permission", "administrative_access"}),
    ("PROD", "prod-bob", {"potentially_unused_access"}),
    ("DEV", "dev-admin", {"broad_permission", "administrative_access"}),
    ("DEV", "dev-charlie", {"potentially_unused_access"}),
]


def _key_risk_groups(findings: list[dict]) -> list[dict]:
    """Curate the intentional POC scenarios, in a fixed, deliberate order.

    Each spec entry pulls only the matching finding(s) for one specific
    principal — e.g. prod-alice's indirect_privilege_path finding, not her
    unrelated potentially_unused_access ones. A broad_permission and
    administrative_access finding for the same principal collapse into one
    entry with a combined rule label rather than two near-identical rows.
    """
    key_risks = []
    for account_label, principal_name, rule_filter in _KEY_RISK_SPEC:
        matches = [
            f
            for f in findings
            if f.get("account_name") == account_label
            and f.get("principal", {}).get("name") == principal_name
            and f.get("rule") in rule_filter
        ]
        if not matches:
            continue
        rules_present = {m["rule"] for m in matches}
        key_risks.append({**matches[0], "rule_display": " / ".join(sorted(rules_present))})

    return key_risks


def _key_risk_html(finding: dict) -> str:
    account_label = finding.get("account_name", "?")
    account_id = finding.get("account_id", "?")
    principal = finding.get("principal", {})
    level = _risk_level(finding.get("rule", ""))

    chain = _escalation_chain(finding.get("detail", "")) if finding.get("rule") == "indirect_privilege_path" else None
    chain_html = ""
    if chain:
        steps = "".join(
            f'<div style="padding:0.15rem 0;">{_esc(step)}</div>'
            + ('<div style="color:#a1a1aa;">&darr;</div>' if i < len(chain) - 1 else "")
            for i, step in enumerate(chain)
        )
        chain_html = (
            f'<div style="margin-top:0.5rem;font-family:ui-monospace,monospace;font-size:0.85rem;'
            f'background:#fafafa;border:1px solid #e4e4e7;border-radius:6px;padding:0.6rem 0.9rem;">'
            f"{steps}"
            f'<div style="color:#a1a1aa;">&darr;</div>'
            f'<div style="font-weight:700;color:#b91c1c;">Administrative Access</div></div>'
        )

    return f"""
    <div style="border:1px solid #e4e4e7;border-radius:8px;padding:0.9rem 1.1rem;margin-bottom:0.7rem;background:#fff;">
      <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
        {_account_badge(account_label, account_id)}
        {_risk_pill(level)}
        <span style="font-weight:600;">{_esc(principal.get('name', '-'))}</span>
        <span style="color:#a1a1aa;">({_esc(principal.get('type', '-'))})</span>
        <span style="color:#71717a;font-size:0.82rem;">&mdash; {_esc(finding.get('rule_display', finding.get('rule', '-')))}</span>
      </div>
      <div style="margin-top:0.4rem;color:#3f3f46;font-size:0.9rem;">{_esc(finding.get('detail', '-'))}</div>
      {chain_html}
    </div>"""


def _finding_row(finding: dict) -> str:
    account_label = finding.get("account_name", "?")
    principal = finding.get("principal", {})
    return (
        "<tr>"
        f"<td>{_account_badge(account_label)}</td>"
        f"<td>{_esc(finding.get('rule', '-'))}</td>"
        f"<td>{_esc(principal.get('name', '-'))} ({_esc(principal.get('type', '-'))})</td>"
        f"<td style='font-size:0.78rem;color:#71717a;'>{_esc(finding.get('policy_id', '-'))}</td>"
        f"<td>{_attribution_text(finding.get('attribution'))}</td>"
        f"<td>{_esc(finding.get('detail', '-'))}</td>"
        "</tr>"
    )


def _drilldown_card(account: dict, finding_count: int) -> str:
    label = account.get("account_label", "?")
    account_id = account.get("account_id", "?")
    color = _account_color(label)
    link = f"{label}/REPORT.html"
    return f"""
    <div style="border:1px solid #e4e4e7;border-left:4px solid {color};border-radius:8px;
                padding:1rem 1.25rem;min-width:220px;background:#fff;">
      {_account_badge(label, account_id)}
      <div style="margin-top:0.4rem;color:#3f3f46;">{_esc(finding_count)} findings</div>
      <div style="margin-top:0.6rem;">
        <a href="{_esc(link)}" style="color:#1d4ed8;font-weight:600;text-decoration:none;">
          View Detailed {_esc(label)} Report &rarr;
        </a>
      </div>
    </div>"""


def _collapsed_account_section(account: dict, account_findings: list[dict]) -> str:
    label = account.get("account_label", "?")
    rows = "".join(_finding_row(f) for f in account_findings) or "<tr><td colspan='6'>No findings.</td></tr>"
    return f"""
    <details style="margin-bottom:0.6rem;border:1px solid #e4e4e7;border-radius:8px;background:#fff;">
      <summary style="cursor:pointer;padding:0.75rem 1rem;font-weight:600;list-style:none;">
        {_account_badge(label, account.get('account_id'))}
        <span style="margin-left:0.5rem;">&mdash; {_esc(len(account_findings))} findings</span>
      </summary>
      <div style="padding:0 1rem 1rem;overflow-x:auto;">
        <table style="border-collapse:collapse;width:100%;font-size:0.85rem;">
          <tr>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Account</th>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Rule</th>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Principal</th>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Policy ID</th>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Attribution</th>
            <th style="text-align:left;padding:5px 8px;border-bottom:2px solid #e4e4e7;">Detail</th>
          </tr>
          {rows}
        </table>
      </div>
    </details>"""


def _stat(value, label: str) -> str:
    return (
        f'<div style="padding:0.6rem 1.1rem;border-right:1px solid #e4e4e7;">'
        f'<div style="font-size:1.35rem;font-weight:700;">{_esc(value)}</div>'
        f'<div style="font-size:0.75rem;color:#71717a;letter-spacing:0.02em;">{_esc(label)}</div></div>'
    )


def _build_html(aggregate: dict) -> str:
    accounts = aggregate.get("accounts", [])
    findings = aggregate.get("findings", [])

    account_cards = "".join(
        _account_card_html(account, _findings_for_account(findings, account.get("account_id")))
        for account in accounts
    ) or "<p>No accounts audited.</p>"

    key_risks = _key_risk_groups(findings)
    key_risk_html = "".join(_key_risk_html(f) for f in key_risks) or "<p>No key risks identified.</p>"

    drilldowns = "".join(
        _drilldown_card(account, account.get("finding_count", len(_findings_for_account(findings, account.get("account_id")))))
        for account in accounts
        if account.get("status") == "success"
    ) or "<p>No successfully audited accounts to drill into.</p>"

    collapsed_sections = "".join(
        _collapsed_account_section(account, _findings_for_account(findings, account.get("account_id")))
        for account in accounts
    ) or "<p>No findings.</p>"
    if not findings:
        collapsed_sections = "<p>No findings.</p>"

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Sentinel — Multi-Account Security Audit</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0; padding: 2.5rem; background: #f4f4f5; color: #18181b; line-height: 1.5;
  }}
  .page {{ max-width: 980px; margin: 0 auto; }}
  h1 {{ margin: 0; font-size: 1.7rem; }}
  h2 {{ font-size: 1.05rem; text-transform: uppercase; letter-spacing: 0.04em; color: #52525b;
        margin: 2.2rem 0 0.8rem; }}
  .eyebrow {{ color: #71717a; font-size: 0.85rem; margin: 0.15rem 0 1.2rem; }}
  .stat-row {{ display: flex; flex-wrap: wrap; border: 1px solid #e4e4e7; border-radius: 8px;
               background: #fff; width: fit-content; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .summary {{ color: #3f3f46; max-width: 70ch; }}
  table {{ border-collapse: collapse; }}
  a {{ color: #1d4ed8; }}
</style>
</head>
<body>
<div class="page">

  <h1>Sentinel</h1>
  <p class="eyebrow">Multi-Account IAM Security Audit</p>

  <div class="stat-row">
    {_stat(aggregate.get('management_account_id', '?'), 'MANAGEMENT ACCOUNT')}
    {_stat(len(accounts), 'ACCOUNTS AUDITED')}
    {_stat(aggregate.get('accounts_succeeded', 0), 'SUCCESSFUL')}
    {_stat(aggregate.get('accounts_failed', 0), 'FAILED')}
    {_stat(aggregate.get('total_findings', 0), 'TOTAL FINDINGS')}
  </div>

  <h2>Executive Summary</h2>
  <p class="summary">Sentinel audited each AWS account independently and combined the results
  while preserving the source account for every finding.</p>

  <h2>Account Overview</h2>
  <div class="cards">{account_cards}</div>

  <h2>Key Security Risks</h2>
  {key_risk_html}

  <h2>Account Drill-Down</h2>
  <div class="cards">{drilldowns}</div>

  <h2>All Findings</h2>
  {collapsed_sections}

</div>
</body>
</html>
"""


def render_multi_account_report(combined_findings_path: Path, output_path: Path) -> Path:
    """Render output/MULTI_ACCOUNT_REPORT.html from an existing combined_findings.json.

    Reads the file as-is — never recomputes or mutates it, never embeds a
    graph, never writes to any per-account output. A failed account entry
    renders as a failed card, not an error; an empty findings list renders
    an explicit "no findings" state rather than a blank/broken page.
    """
    aggregate = json.loads(Path(combined_findings_path).read_text())
    html_content = _build_html(aggregate)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path
