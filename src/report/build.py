"""Human-facing demo report — presentation layer only.

Reads already-generated outputs (findings.json, evidence_package.json,
explanations.json, the raw collector data, and the already-rendered
graph.html) and assembles one self-contained HTML file. Invents nothing:
every number and every finding/explanation/evidence entry shown here is
read verbatim from what earlier stages already produced. No AWS calls, no
new relationships, no re-derivation of findings.

Designed to be readable top-to-bottom in one pass: executive summary and the
one headline risk first, compact finding cards next, the embedded graph
(src/graph/visualize.py's actual graph.html, not a second implementation),
then principal-by-principal and source-by-source detail for anyone who wants
to dig further. Deterministic findings and AI explanations are always
visually distinct — the AI never appears to be the source of a finding.
"""

import base64
import html
import json
from pathlib import Path

from src.ai.explain import _finding_id

SEVERITY_RULES = ("indirect_privilege_path", "administrative_access", "broad_permission")
REVIEW_RULE = "potentially_unused_access"
PRIORITY_ORDER = ["indirect_privilege_path", "administrative_access", "broad_permission", "potentially_unused_access"]

FINDING_TYPE_LABELS = {
    "indirect_privilege_path": "Privilege Escalation Path",
    "administrative_access": "Administrative Access",
    "broad_permission": "Broad Permission",
    "potentially_unused_access": "Potentially Unused Access",
}

SERVICE_LINKED_ROLE_PREFIX = "AWSServiceRoleFor"
PRIORITY_PRINCIPAL_NAMES = ["alice", "bob", "charlie", "developerrole", "adminrole"]

TOOLTIPS = {
    "CAN_ASSUME": "Can assume this IAM role",
    "HAS_POLICY": "This policy is attached to the principal",
    "group_inherited": "Permission comes through a group membership, not a direct attachment",
    "direct_attached": "Policy is attached directly to this principal",
    "inline": "Policy is embedded directly on this principal, not a separate managed policy",
    "IAM Last Accessed": "AWS data on which services/actions a principal has attempted to use",
    "Access Analyzer": "AWS service that flags resources shared with entities outside this account",
}


def _esc(value) -> str:
    # quote=False: used for text content, not attributes (the one attribute
    # use below escapes separately) — quoting here would turn a real
    # apostrophe like "charlie's access" into &#x27; in visible text.
    return html.escape(str(value), quote=False) if value is not None else ""


def _term(label: str) -> str:
    """A term with a native hover tooltip explaining it in plain English."""
    tooltip = TOOLTIPS.get(label, "")
    if not tooltip:
        return _esc(label)
    return f'<abbr class="term" title="{html.escape(tooltip, quote=True)}">{_esc(label)}</abbr>'


def _friendly_name(identifier: str) -> str:
    """Short display name for a policy/role ARN or synthetic inline id."""
    if not identifier:
        return ""
    if ":inline:" in identifier:
        return identifier.split(":inline:")[-1]
    return identifier.rsplit("/", 1)[-1]


def _finding_lookup(explanations: list[dict]) -> dict[str, dict]:
    return {e["finding_id"]: e for e in explanations}


CSS = """
:root {
  --bg: #f4f5f7; --card: #ffffff; --border: #dfe1e6; --text: #172b4d; --muted: #6b778c;
  --risk: #de350b; --review: #ffab00; --clean: #36b37e; --accent: #0052cc;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.45; }
header#topnav { position: sticky; top: 0; z-index: 100; background: #091e42; color: #fff; padding: 10px 20px;
  display: flex; align-items: center; gap: 4px; flex-wrap: wrap; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
header#topnav .title { font-weight: 700; font-size: 15px; margin-right: 16px; }
header#topnav a { color: #b3c7e6; text-decoration: none; font-size: 13px; padding: 5px 10px; border-radius: 4px; }
header#topnav a:hover { background: rgba(255,255,255,0.12); color: #fff; }
main { max-width: 1080px; margin: 0 auto; padding: 28px 20px 90px; }
section { margin-bottom: 48px; }
h2 { font-size: 19px; margin-bottom: 4px; }
h2 .section-num { color: var(--muted); font-weight: 400; }
.section-sub { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
h3 { font-size: 13px; color: var(--muted); margin: 16px 0 6px; text-transform: uppercase; letter-spacing: 0.04em; }
abbr.term { text-decoration: none; border-bottom: 1px dotted var(--muted); cursor: help; }

/* Executive summary */
.hero-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 20px; }
.hero-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; text-align: center; }
.hero-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
.hero-card .value { font-size: 22px; font-weight: 700; margin-top: 4px; }
.hero-card .value.risk { color: var(--risk); }
.hero-card .value.review { color: #a66a00; }
.key-risk { background: #fff5f4; border: 2px solid var(--risk); border-radius: 10px; padding: 18px 22px; margin-bottom: 8px; }
.key-risk .kr-label { font-size: 12px; font-weight: 700; color: var(--risk); text-transform: uppercase; letter-spacing: 0.05em; }
.key-risk .kr-sentence { font-size: 16px; margin: 8px 0 14px; }
.chain-diagram { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 13.5px; background: #ffffff;
  border: 1px solid #f3c8c2; border-radius: 8px; padding: 12px 16px; white-space: pre; overflow-x: auto; }
.no-risk { background: #eafcf3; border: 2px solid var(--clean); border-radius: 10px; padding: 16px 20px; font-size: 14px; }

/* Badges */
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }
.badge-risk { background: var(--risk); }
.badge-review { background: var(--review); color: #3a2a00; }
.badge-clean { background: var(--clean); }

/* Compact finding cards */
.finding-card { background: var(--card); border: 1px solid var(--border); border-left: 5px solid var(--risk);
  border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; }
.finding-card .fh { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.finding-card .fh .who { font-size: 15.5px; font-weight: 700; }
.finding-card .fh .what { color: var(--muted); font-size: 13px; }
.finding-card .policy-line { font-size: 12.5px; color: var(--muted); margin-top: 2px; }
.label-row { display: flex; gap: 8px; margin-top: 10px; align-items: center; }
.label-tag { font-size: 10px; font-weight: 700; letter-spacing: 0.05em; padding: 2px 6px; border-radius: 3px; }
.label-tag.det { background: #dfe1e6; color: #172b4d; }
.label-tag.ai { background: #deebff; color: #0052cc; }
.one-liner { font-size: 13.5px; margin: 4px 0 0; }
.recommended { font-size: 13px; margin-top: 8px; background: #f4fff8; border-left: 3px solid var(--clean); padding: 6px 10px; }
details.evidence-toggle { margin-top: 10px; }
details.evidence-toggle summary { cursor: pointer; font-size: 12px; color: var(--accent); font-weight: 600; }
details.evidence-toggle .kv { display: grid; grid-template-columns: 150px 1fr; gap: 5px 12px; font-size: 12.5px; margin-top: 10px; }
details.evidence-toggle .kv .k { color: var(--muted); }

/* Unused-access table */
details.unused-table { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 4px 18px 14px; }
details.unused-table summary { cursor: pointer; font-weight: 700; padding: 10px 0; font-size: 14.5px; }
table.simple { width: 100%; border-collapse: collapse; margin-top: 4px; font-size: 12.5px; }
table.simple th, table.simple td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
table.simple th { color: var(--muted); font-weight: 600; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; background: #e6effc; color: #0747a6; }
.pill.group { background: #eae6ff; color: #403294; }
details.row-detail summary { cursor: pointer; color: var(--accent); font-size: 11.5px; }

/* Graph section */
.hero-note { background: #fffbe6; border: 1px solid #ffe380; border-radius: 8px; padding: 12px 16px; font-size: 13.5px; margin-bottom: 14px; }
#graph-frame { width: 100%; height: 780px; border: 1px solid var(--border); border-radius: 8px; }
.checklist { list-style: none; padding: 0; margin: 12px 0; }
.checklist li { padding: 3px 0; font-size: 13.5px; }
.checklist li.pass::before { content: "✓ "; color: var(--clean); font-weight: 700; }
.checklist li.fail::before { content: "✗ "; color: var(--risk); font-weight: 700; }

/* Principals */
details.principal { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; margin-bottom: 8px; }
details.principal summary { cursor: pointer; font-weight: 700; display: flex; gap: 10px; align-items: center; }
details.principal summary .ptype { font-weight: 400; color: var(--muted); font-size: 12px; }
details.principal summary .priority-star { color: var(--accent); }
details.service-linked-group { background: #f4f5f7; border: 1px dashed var(--border); border-radius: 8px; padding: 8px 16px; margin-top: 12px; }
details.service-linked-group summary { cursor: pointer; color: var(--muted); font-size: 13px; }
input#principal-search { width: 100%; max-width: 360px; padding: 7px 10px; border: 1px solid var(--border);
  border-radius: 6px; font-size: 13px; margin-bottom: 12px; }

/* Evidence + limitations */
.evidence-source { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 10px; }
.evidence-source .es-title { font-weight: 700; font-size: 14.5px; }
.evidence-source .es-status { font-size: 13px; margin-top: 4px; }
.evidence-source .es-status.ok::before { content: "✓ "; color: var(--clean); }
.evidence-source ul { margin: 6px 0 0 18px; font-size: 13px; color: var(--muted); }
.limitations { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; }
.limitations li { margin-bottom: 6px; font-size: 13.5px; }
"""


# --- Executive summary + key risk -------------------------------------------


def _escalation_chain(finding: dict, evidence_package: dict) -> list[str]:
    """Walk CAN_ASSUME hops from a finding's principal, using only the
    relationships already computed into the evidence package."""
    package = evidence_package.get("packages", {}).get(finding["principal"]["id"])
    if package is None:
        return [finding["principal"]["name"]]
    adjacency = {r["from"]: r["to"] for r in package["relationships"] if r["relationship"] == "CAN_ASSUME"}
    chain = [finding["principal"]["name"]]
    current = finding["principal"]["name"]
    for _ in range(10):
        nxt = adjacency.get(current)
        if not nxt or nxt in chain:
            break
        chain.append(nxt)
        current = nxt
    return chain


def _key_risk_html(findings: list[dict], evidence_package: dict) -> str:
    escalation = next((f for f in findings if f["rule"] == "indirect_privilege_path"), None)
    if escalation is None:
        return '<div class="no-risk">No privilege-escalation path was found in this run.</div>'

    chain = _escalation_chain(escalation, evidence_package)
    policy_name = _friendly_name(escalation.get("policy_id", ""))
    intermediates = chain[1:-1]
    via_text = " → ".join(intermediates) if intermediates else "a role it can assume"
    sentence = (
        f"<strong>{_esc(chain[0])}</strong> can indirectly reach an administrative role "
        f"(<strong>{_esc(chain[-1])}</strong>) through <strong>{_esc(via_text)}</strong>, "
        f"which grants unrestricted access via <strong>{_esc(policy_name)}</strong>."
    )

    diagram_lines = [chain[0]]
    for hop in chain[1:]:
        diagram_lines.append(f"  ↓ {_term('CAN_ASSUME')}")
        diagram_lines.append(hop)
    diagram_lines.append(f"  ↓ {_term('HAS_POLICY')}")
    diagram_lines.append(_esc(policy_name))
    diagram_lines.append("  ↓")
    diagram_lines.append("Action=* / Resource=*")
    diagram = "\n".join(diagram_lines)

    return f"""
    <div class="key-risk">
      <div class="kr-label">Key Risk</div>
      <div class="kr-sentence">{sentence}</div>
      <div class="chain-diagram">{diagram}</div>
    </div>
    """


def _summary_section(context: dict) -> str:
    identity = context["identity"]
    normalized = context["normalized"]
    findings = context["findings"]
    all_succeeded = all(s.succeeded for s in context["statuses"])
    status_text = "COMPLETE" if all_succeeded else "COMPLETED WITH GAPS"
    status_badge = "badge-clean" if all_succeeded else "badge-review"

    high_risk_count = sum(1 for f in findings if f["rule"] in SEVERITY_RULES)
    review_count = sum(1 for f in findings if f["rule"] == REVIEW_RULE)

    cards = [
        ("Account", identity["account_id"], ""),
        ("Region", identity["region"], ""),
        ("Audit Status", f'<span class="badge {status_badge}">{_esc(status_text)}</span>', ""),
        ("Total Findings", len(findings), ""),
        ("High-Risk Findings", high_risk_count, "risk"),
        ("Review Findings", review_count, "review"),
    ]
    card_html = "".join(
        f'<div class="hero-card"><div class="label">{_esc(label)}</div><div class="value {cls}">{value}</div></div>'
        for label, value, cls in cards
    )

    return f"""
    <section id="summary">
      <h2><span class="section-num">1.</span> Sentinel — Executive Summary</h2>
      <p class="section-sub">This audit is read-only. It collected AWS IAM configuration and usage
        evidence and identified access that appears excessive. Findings are decided entirely by
        deterministic code — the AI you'll see later only explains findings, never creates them.</p>
      <div class="hero-cards">{card_html}</div>
      {_key_risk_html(findings, context["evidence_package"])}
    </section>
    """


# --- Findings ----------------------------------------------------------------


def _finding_evidence_details(finding: dict, explanation: dict | None) -> str:
    attribution = finding.get("attribution", {})
    attribution_text = attribution.get("attachment_type", "")
    if attribution.get("source_group_name"):
        attribution_text += f" (via {attribution['source_group_name']})"

    rows = [
        ("Principal ARN", finding["principal"]["id"]),
        ("Policy (full)", finding.get("policy_id", "")),
        ("Attribution", attribution_text),
    ]
    if finding.get("evidence_window"):
        window = finding["evidence_window"]
        rows.append(("Evidence sources", ", ".join(window.get("sources_consulted", []))))
        rows.append(("Evidence note", window.get("note", "")))

    if explanation:
        rows.append(("Supporting evidence", "; ".join(explanation.get("supporting_evidence", [])) or "—"))
        rows.append(("Configured access (AI)", explanation.get("configured_access", "") or "—"))
        rows.append(("Observed activity (AI)", explanation.get("observed_activity", "") or "—"))
        rows.append(("Access path (AI)", explanation.get("access_path", "") or "—"))
        rows.append(("AI-noted limitations", "; ".join(explanation.get("limitations", [])) or "—"))

    kv = "".join(f'<div class="k">{_esc(k)}</div><div>{_esc(v)}</div>' for k, v in rows if v)
    return f"""
    <details class="evidence-toggle">
      <summary>View evidence</summary>
      <div class="kv">{kv}</div>
    </details>
    """


def _finding_card(finding: dict, explanation: dict | None) -> str:
    rule = finding["rule"]
    policy_name = _friendly_name(finding.get("policy_id", ""))
    badge_class = "badge-risk" if rule in SEVERITY_RULES else "badge-review"
    severity_label = "HIGH RISK" if rule in SEVERITY_RULES else "REVIEW"

    ai_block = ""
    if explanation:
        recommended = explanation.get("recommended_action", "")
        ai_block = f"""
        <div class="label-row"><span class="label-tag ai">AI EXPLANATION</span></div>
        <p class="one-liner">{_esc(explanation.get('explanation', ''))}</p>
        {f'<div class="recommended"><strong>Recommended action:</strong> {_esc(recommended)}</div>' if recommended else ''}
        """
    else:
        ai_block = '<p class="one-liner" style="color:var(--muted);font-style:italic;">No AI explanation available.</p>'

    return f"""
    <div class="finding-card">
      <div class="fh">
        <span class="who">{_esc(finding['principal']['name'])}</span>
        <span class="what">{_esc(FINDING_TYPE_LABELS.get(rule, rule))}</span>
        <span class="badge {badge_class}">{severity_label}</span>
      </div>
      <div class="policy-line">Policy: <strong>{_esc(policy_name)}</strong></div>
      <div class="label-row"><span class="label-tag det">DETERMINISTIC FINDING</span></div>
      <p class="one-liner">{_esc(finding.get('detail', ''))}</p>
      {ai_block}
      {_finding_evidence_details(finding, explanation)}
    </div>
    """


def _unused_access_table(findings: list[dict], explanations_by_id: dict) -> str:
    if not findings:
        return ""
    rows = []
    for finding in findings:
        attribution = finding.get("attribution", {})
        attribution_html = _term(attribution.get("attachment_type", ""))
        if attribution.get("source_group_name"):
            attribution_html += f" ({_esc(attribution['source_group_name'])})"

        explanation = explanations_by_id.get(_finding_id(finding))
        detail_toggle = ""
        if explanation:
            detail_toggle = f"""
            <details class="row-detail">
              <summary>AI notes</summary>
              <div style="font-size:12px;margin-top:4px;">{_esc(explanation.get('explanation', ''))}
              {f"<br><strong>Recommended:</strong> {_esc(explanation.get('recommended_action', ''))}" if explanation.get('recommended_action') else ''}
              </div>
            </details>
            """
        rows.append(
            f"<tr><td>{_esc(finding['principal']['name'])}</td>"
            f"<td>{_esc(_friendly_name(finding.get('policy_id', '')))}</td>"
            f"<td>{attribution_html}</td>"
            f"<td>No activity observed{detail_toggle}</td></tr>"
        )

    return f"""
    <details class="unused-table">
      <summary>{FINDING_TYPE_LABELS[REVIEW_RULE]} ({len(findings)})</summary>
      <table class="simple">
        <tr><th>Principal</th><th>Policy</th><th>Attribution</th><th>Evidence</th></tr>
        {''.join(rows)}
      </table>
    </details>
    """


def _findings_section(context: dict) -> str:
    findings = context["findings"]
    explanations_by_id = _finding_lookup(context["explanations"])

    grouped: dict[str, list[dict]] = {}
    for f in findings:
        grouped.setdefault(f["rule"], []).append(f)

    cards_html = ""
    for rule in PRIORITY_ORDER:
        if rule == REVIEW_RULE:
            continue
        for finding in grouped.get(rule, []):
            explanation = explanations_by_id.get(_finding_id(finding))
            cards_html += _finding_card(finding, explanation)

    unused_html = _unused_access_table(grouped.get(REVIEW_RULE, []), explanations_by_id)

    return f"""
    <section id="findings">
      <h2><span class="section-num">2.</span> Security Findings</h2>
      <p class="section-sub">Ordered by severity. Each card separates what deterministic code
        found from how the AI explains it — the AI cannot create, remove, or reinterpret a finding.</p>
      {cards_html or '<p>No high-risk or administrative-access findings in this run.</p>'}
      {unused_html}
    </section>
    """


# --- Graph section -----------------------------------------------------------


def _demo_checklist(findings: list[dict], evidence_package: dict, normalized: dict) -> str:
    escalation = next((f for f in findings if f["rule"] == "indirect_privilege_path"), None)
    items: list[tuple[str, bool]] = []
    if escalation:
        chain = _escalation_chain(escalation, evidence_package)
        if len(chain) >= 2:
            items.append((f"{chain[0]} can reach {chain[1]}", True))
        if len(chain) >= 3:
            items.append((f"{chain[-2]} can reach {chain[-1]}", True))
        policy_name = _friendly_name(escalation.get("policy_id", ""))
        items.append((f"{chain[-1]} has unrestricted access ({policy_name})", True))

        package = evidence_package.get("packages", {}).get(escalation["principal"]["id"], {})
        reached = {r["to"] for r in package.get("relationships", [])}
        untrusted_roles = [r for r in normalized.get("roles", []) if "untrusted" in r["name"].lower()]
        for role in untrusted_roles:
            items.append((f"{chain[0]} cannot assume {role['name']}", role["name"] not in reached))

    rows = "".join(f'<li class="{"pass" if ok else "fail"}">{_esc(label)}</li>' for label, ok in items)
    return f'<ul class="checklist">{rows}</ul>' if rows else ""


def _graph_section(context: dict, graph_html_content: str) -> str:
    encoded = base64.b64encode(graph_html_content.encode("utf-8")).decode("ascii")
    findings = context["findings"]
    evidence_package = context["evidence_package"]
    checklist = _demo_checklist(findings, evidence_package, context["normalized"])

    escalation = next((f for f in findings if f["rule"] == "indirect_privilege_path"), None)
    if escalation:
        chain = _escalation_chain(escalation, evidence_package)
        policy_name = _friendly_name(escalation.get("policy_id", ""))
        path_lines = "\n→ ".join(chain[1:]) if len(chain) > 1 else ""
        path_diagram = f"{chain[0]}\n→ {path_lines}\n→ {policy_name}\n→ Action=* / Resource=*"
    else:
        path_diagram = "No privilege-escalation path in this run."

    return f"""
    <section id="graph">
      <h2><span class="section-num">3.</span> Security Graph</h2>
      <p class="section-sub"><strong>What this graph shows:</strong> users and roles are connected
        to the policies and permissions they can reach. {_term('CAN_ASSUME')} edges represent
        role-assumption paths. {_term('HAS_POLICY')} edges show policy attachment.</p>
      <div class="hero-note">
        <strong>Key Investigation Path</strong>
        <div class="chain-diagram" style="margin-top:8px;">{_esc(path_diagram)}</div>
      </div>
      <h3>Demo checklist</h3>
      {checklist}
      <p class="section-sub">Security View (default) hides AWS service-linked roles and permission
        detail unrelated to a flagged finding. Use the Full Graph toggle inside the graph below for
        the complete picture — nothing here is a second graph implementation, it's the same
        graph.html embedded as-is.</p>
      <iframe id="graph-frame" src="data:text/html;charset=utf-8;base64,{encoded}"
        sandbox="allow-scripts allow-same-origin"></iframe>
    </section>
    """


# --- Principal investigation --------------------------------------------------


def _principal_card(package: dict, findings_for_principal: list[dict]) -> str:
    principal = package["principal"]
    configured = package["configured_access"]
    relationships = package["relationships"]
    activity = package["observed_activity"]
    last_accessed = package["last_accessed"]

    access_rows = "".join(
        f"<tr><td>{_esc(_friendly_name(a['policy']))}</td>"
        f"<td><span class='pill{' group' if a['attachment_type'] == 'group_inherited' else ''}'>"
        f"{_term(a['attachment_type'])}{' via ' + _esc(a['source_group_name']) if a.get('source_group_name') else ''}</span></td>"
        f"<td>{_esc(', '.join(sorted({p['effect'] for p in a.get('permissions', [])})) or '—')}</td></tr>"
        for a in configured
    ) or "<tr><td colspan='3'>No configured access</td></tr>"

    rel_text = "; ".join(f"{r['from']} → {r['to']}" for r in relationships) or "none"

    events = activity.get("events", [])
    event_text = "; ".join(f"{e['event_name']}" for e in events[:5])
    if len(events) > 5:
        event_text += f" … +{len(events) - 5} more"
    event_text = event_text or "no CloudTrail activity attributed to this principal"

    la_rows = "".join(
        f"<tr><td>{_esc(s['service'])}</td><td>{_esc(s.get('last_authenticated') or 'never observed')}</td></tr>"
        for s in last_accessed
    ) or "<tr><td colspan='2'>No last-accessed data</td></tr>"

    findings_text = ", ".join(FINDING_TYPE_LABELS.get(f["rule"], f["rule"]) for f in findings_for_principal) or "none"

    safe_name_attr = html.escape(principal["name"], quote=True).lower()
    priority_star = ' <span class="priority-star">★</span>' if principal["name"].lower() in PRIORITY_PRINCIPAL_NAMES else ""
    return f"""
    <details class="principal" data-name="{safe_name_attr}">
      <summary>{_esc(principal['name'])}{priority_star} <span class="ptype">({_esc(principal['type'])})</span></summary>
      <h3>Findings</h3>
      <p style="font-size:13px;">{_esc(findings_text)}</p>
      <h3>Configured Access</h3>
      <table class="simple"><tr><th>Policy</th><th>Attribution</th><th>Effect(s)</th></tr>{access_rows}</table>
      <h3>Relationships</h3>
      <p style="font-size:13px;">{_esc(rel_text)}</p>
      <h3>Observed Activity</h3>
      <p style="font-size:13px;">{_esc(event_text)}</p>
      <h3>Last Accessed</h3>
      <table class="simple"><tr><th>Service</th><th>Last authenticated</th></tr>{la_rows}</table>
    </details>
    """


def _principals_section(evidence_package: dict, findings: list[dict]) -> str:
    findings_by_principal: dict[str, list[dict]] = {}
    for f in findings:
        findings_by_principal.setdefault(f["principal"]["id"], []).append(f)

    packages = list(evidence_package.get("packages", {}).values())

    def is_service_linked(p):
        return p["principal"]["type"] == "role" and p["principal"]["name"].startswith(SERVICE_LINKED_ROLE_PREFIX)

    def priority_key(p):
        name = p["principal"]["name"].lower()
        return (PRIORITY_PRINCIPAL_NAMES.index(name) if name in PRIORITY_PRINCIPAL_NAMES else 99, name)

    def card_for(p):
        return _principal_card(p, findings_by_principal.get(p["principal"]["id"], []))

    regular = sorted((p for p in packages if not is_service_linked(p)), key=priority_key)
    service_linked = sorted((p for p in packages if is_service_linked(p)), key=lambda p: p["principal"]["name"].lower())

    cards = "".join(card_for(p) for p in regular)
    service_cards = "".join(card_for(p) for p in service_linked)
    service_block = (
        f"""
        <details class="service-linked-group">
          <summary>AWS service-linked roles ({len(service_linked)}) — not part of the security story</summary>
          {service_cards}
        </details>
        """
        if service_linked
        else ""
    )

    return f"""
    <section id="principals">
      <h2><span class="section-num">4.</span> Principal Investigation</h2>
      <p class="section-sub">★ marks the principals most useful for a demo walkthrough. Click any
        row to expand its access, relationships, and activity.</p>
      <input id="principal-search" type="text" placeholder="Filter by name…">
      <div id="principal-list">{cards}</div>
      {service_block}
      <script>
        document.getElementById("principal-search").addEventListener("input", function () {{
          var term = this.value.trim().toLowerCase();
          document.querySelectorAll("#principal-list details.principal").forEach(function (el) {{
            el.style.display = (!term || el.dataset.name.indexOf(term) !== -1) ? "" : "none";
          }});
        }});
      </script>
    </section>
    """


# --- Evidence + limitations ---------------------------------------------------


def _activity_section(context: dict) -> str:
    normalized = context["normalized"]
    last_accessed_statuses = context["last_accessed_statuses"]
    cloudtrail_data = context["cloudtrail_data"]
    analyzer_data = context["analyzer_data"]

    succeeded = sum(1 for s in last_accessed_statuses if s.succeeded)
    window = cloudtrail_data.get("evidence_window", {})
    analyzers = analyzer_data.get("analyzers", [])

    sources = [
        (
            "IAM Authorization",
            True,
            [
                f"{len(normalized['users'])} users, {len(normalized['groups'])} groups, "
                f"{len(normalized['roles'])} roles, {len(normalized['policies'])} policies collected"
            ],
        ),
        (
            _term("IAM Last Accessed"),
            succeeded == len(last_accessed_statuses),
            [f"{succeeded}/{len(last_accessed_statuses)} principals succeeded"],
        ),
        (
            "CloudTrail",
            bool(cloudtrail_data.get("events") is not None),
            [
                f"{len(cloudtrail_data.get('events', []))} management events",
                f"{window.get('lookback_days', '?')}-day window",
                cloudtrail_data.get("region", ""),
            ],
        ),
        (
            _term("Access Analyzer"),
            bool(analyzers),
            [
                f"{analyzers[0]['status'] if analyzers else 'no active analyzer'}",
                f"{len(analyzer_data.get('findings', []))} external-access findings",
            ],
        ),
    ]

    blocks = []
    for title, ok, lines in sources:
        status_html = '<span class="es-status ok">Collected</span>' if ok else '<span class="es-status">Not fully collected</span>'
        list_html = "".join(f"<li>{_esc(line)}</li>" for line in lines if line)
        blocks.append(
            f"""<div class="evidence-source"><div class="es-title">{title}</div>
                {status_html}<ul>{list_html}</ul></div>"""
        )

    return f"""
    <section id="activity">
      <h2><span class="section-num">5.</span> Evidence Summary</h2>
      <p class="section-sub">What was collected and what it contributed — not the raw records themselves.</p>
      {''.join(blocks)}
    </section>
    """


def _limitations_section(evidence_package: dict) -> str:
    packages = list(evidence_package.get("packages", {}).values())
    limitations = packages[0]["evidence_limitations"] if packages else []
    items = "".join(f"<li>{_esc(item)}</li>" for item in limitations)
    return f"""
    <section id="limitations">
      <h2><span class="section-num">6.</span> Evidence Limitations</h2>
      <p class="section-sub">Shown once here — not repeated inside every finding above.</p>
      <div class="limitations"><ul>{items or '<li>No limitations recorded.</li>'}</ul></div>
    </section>
    """


NAV_HTML = """
<header id="topnav">
  <span class="title">Sentinel</span>
  <a href="#summary">Summary</a>
  <a href="#findings">Findings</a>
  <a href="#graph">Graph</a>
  <a href="#principals">Principal Access</a>
  <a href="#activity">Evidence</a>
  <a href="#limitations">Limitations</a>
</header>
"""


def render_report(context: dict, graph_html_path: Path, output_path: Path) -> Path:
    """Assemble the self-contained demo report from already-generated outputs.

    `context` carries the same in-memory objects main.py already produced
    this run (identity, normalized, findings, evidence_package, explanations,
    analyzer_data, last_accessed_data/statuses, cloudtrail_data, statuses,
    finished timestamp) — nothing is recomputed or re-derived here.
    """
    graph_html_content = graph_html_path.read_text(encoding="utf-8")

    body = "".join(
        [
            NAV_HTML,
            "<main>",
            _summary_section(context),
            _findings_section(context),
            _graph_section(context, graph_html_content),
            _principals_section(context["evidence_package"], context["findings"]),
            _activity_section(context),
            _limitations_section(context["evidence_package"]),
            "</main>",
        ]
    )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel — AWS IAM Security Audit Report</title>
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return output_path
