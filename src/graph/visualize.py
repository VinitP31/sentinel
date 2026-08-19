"""Interactive HTML visualization, with a toggle between two views.

Reads the already-built NetworkX graph and already-computed findings as its
only sources of truth — invents no new relationships, makes no AWS calls,
and never mutates the graph or findings it's given (styled deep copies are
rendered instead). graph.json itself is untouched by anything here.

Security View (default): users, groups, and roles other than AWS
service-linked roles, plus their policies. Permission/resource nodes are
shown only for policies a broad_permission / administrative_access /
indirect_privilege_path finding actually names — so the one wildcard chain
that matters (e.g. AdminRole -> POC-Admin-Access -> Allow * -> *) stays
visible while the rest of the account's permission/resource detail (which
dominates node count) stays out of the way.

Full Graph: the complete graph, unfiltered — a toggle away, not a second
file, so nothing needs to be regenerated to switch.
"""

import copy
import html as html_escape
import json
from pathlib import Path

import networkx as nx
from pyvis.network import Network

SERVICE_LINKED_ROLE_PREFIX = "AWSServiceRoleFor"

RISK_COLOR = "#DE350B"       # red — broad_permission / administrative_access / indirect_privilege_path
REVIEW_COLOR = "#FFAB00"     # amber — potentially_unused_access only
CLEAN_COLOR = "#36B37E"      # green — no findings at all
GROUP_COLOR = "#8993A4"      # neutral gray — groups aren't a finding target themselves
PERMISSION_COLOR = "#8993A4"
RESOURCE_COLOR = "#E8547A"

RISK_RULES = {"broad_permission", "administrative_access", "indirect_privilege_path"}
REVIEW_RULES = {"potentially_unused_access"}

EDGE_COLORS = {
    "MEMBER_OF": "#8993A4",
    "HAS_POLICY": "#4C9AFF",
    "CAN_ASSUME": "#DE350B",
    "CONTAINS": "#36B37E",
    "TARGETS": "#E8547A",
}
CAN_ASSUME_WIDTH = 4
DEFAULT_EDGE_WIDTH = 1


# --- risk classification (shared by both views) ---------------------------


def _risk_ids(findings: list[dict]) -> tuple[set[str], set[str]]:
    """(risky, review-only) ids — a policy_id or a principal's own id."""
    risky, review = set(), set()
    for finding in findings:
        rule = finding["rule"]
        bucket = risky if rule in RISK_RULES else review if rule in REVIEW_RULES else None
        if bucket is None:
            continue
        bucket.add(finding["principal"]["id"])
        if finding.get("policy_id"):
            bucket.add(finding["policy_id"])
    review -= risky  # a risky node never gets downgraded to "review"
    return risky, review


def _findings_by_node(findings: list[dict]) -> dict[str, list[dict]]:
    by_node: dict[str, list[dict]] = {}
    for finding in findings:
        by_node.setdefault(finding["principal"]["id"], []).append(finding)
        if finding.get("policy_id"):
            by_node.setdefault(finding["policy_id"], []).append(finding)
    return by_node


def _node_color(node_id: str, node_type: str, risky_ids: set[str], review_ids: set[str]) -> str:
    if node_type == "group":
        return GROUP_COLOR
    if node_type == "permission":
        return PERMISSION_COLOR
    if node_type == "resource":
        return RESOURCE_COLOR
    if node_id in risky_ids:
        return RISK_COLOR
    if node_id in review_ids:
        return REVIEW_COLOR
    return CLEAN_COLOR


def _node_label(node_id: str, data: dict) -> str:
    node_type = data.get("node_type")
    if node_type in ("user", "group", "role", "policy"):
        return data.get("name", node_id)
    if node_type == "permission":
        effect = data.get("effect", "?")
        actions = data.get("actions", [])
        return f"{effect}: {actions[0]}" if len(actions) == 1 else f"{effect} ({len(actions)} actions)"
    if node_type == "resource":
        if node_id == "*":
            return "*"
        tail = node_id.rstrip("/*").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        return tail[:30] + ("…" if len(tail) > 30 else "")
    return node_id


def _node_title(node_id: str, data: dict, findings_for_node: list[dict]) -> str:
    lines = [f"type: {data.get('node_type')}", f"name: {data.get('name', node_id)}"]
    if findings_for_node:
        lines.append("findings:")
        for finding in findings_for_node:
            lines.append(f"  - {finding['rule']}: {finding['detail']}")
    else:
        lines.append("findings: none")
    return html_escape.escape("\n".join(lines))


def _edge_title(data: dict) -> str:
    relationship = data.get("relationship", "unknown")
    lines = [f"relationship: {relationship}"]
    for key in ("attachment_type", "source_group_name"):
        value = data.get(key)
        if value:
            lines.append(f"{key}: {value}")
    return html_escape.escape("\n".join(lines))


def _style_copy(graph: nx.DiGraph, findings: list[dict]) -> nx.DiGraph:
    """Return a styled deep copy of graph — never mutate the original."""
    styled = copy.deepcopy(graph)
    risky_ids, review_ids = _risk_ids(findings)
    findings_by_node = _findings_by_node(findings)

    for node_id, data in styled.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        data["color"] = _node_color(node_id, node_type, risky_ids, review_ids)
        data["label"] = _node_label(node_id, data)
        data["title"] = _node_title(node_id, data, findings_by_node.get(node_id, []))
        data["shape"] = "dot"
        data["size"] = 18 if node_type in ("user", "role") else 10 if node_type == "permission" else 14
        data["group"] = node_type

    for _, _, data in styled.edges(data=True):
        relationship = data.get("relationship", "unknown")
        data["color"] = EDGE_COLORS.get(relationship, "#B3BAC5")
        data["title"] = _edge_title(data)
        data["width"] = CAN_ASSUME_WIDTH if relationship == "CAN_ASSUME" else DEFAULT_EDGE_WIDTH
        data["dashes"] = relationship == "MEMBER_OF"
        data["arrows"] = "to"
        if relationship == "CAN_ASSUME":
            data["label"] = "CAN_ASSUME"

    return styled


# --- Security View subset ---------------------------------------------------


def _service_linked_role_ids(graph: nx.DiGraph) -> set[str]:
    return {
        node_id
        for node_id, data in graph.nodes(data=True)
        if data.get("node_type") == "role" and data.get("name", "").startswith(SERVICE_LINKED_ROLE_PREFIX)
    }


def _security_view_node_ids(graph: nx.DiGraph, findings: list[dict]) -> set[str]:
    """Users/groups/non-service-linked roles and policies, plus only the
    permission/resource nodes a risk finding actually names."""
    service_linked_roles = _service_linked_role_ids(graph)
    risk_policy_ids = {
        f["policy_id"] for f in findings if f["rule"] in RISK_RULES and f.get("policy_id")
    }

    holders_by_policy: dict[str, set[str]] = {}
    for u, v, data in graph.edges(data=True):
        if data.get("relationship") == "HAS_POLICY":
            holders_by_policy.setdefault(v, set()).add(u)
    # A policy held only by service-linked roles is noise the same way the
    # roles themselves are; a policy shared with a real principal stays.
    excluded_policies = {
        policy_id
        for policy_id, holders in holders_by_policy.items()
        if holders and holders <= service_linked_roles
    }

    keep: set[str] = set()
    for node_id, data in graph.nodes(data=True):
        node_type = data.get("node_type")
        if node_type in ("user", "group"):
            keep.add(node_id)
        elif node_type == "role" and node_id not in service_linked_roles:
            keep.add(node_id)
        elif node_type == "policy" and node_id not in excluded_policies:
            keep.add(node_id)

    kept_permissions = {
        v for u, v, data in graph.edges(data=True)
        if data.get("relationship") == "CONTAINS" and u in risk_policy_ids
    }
    kept_resources = {
        v for u, v, data in graph.edges(data=True)
        if data.get("relationship") == "TARGETS" and u in kept_permissions
    }
    return keep | kept_permissions | kept_resources


# --- vis.js data + HTML assembly -------------------------------------------


def _to_vis_nodes(graph: nx.DiGraph, node_ids: set[str]) -> list[dict]:
    return [
        {"id": node_id, **{k: v for k, v in data.items() if k not in ("node_type", "name")}}
        for node_id, data in graph.nodes(data=True)
        if node_id in node_ids
    ]


def _to_vis_edges(graph: nx.DiGraph, node_ids: set[str]) -> list[dict]:
    edges = []
    for u, v, data in graph.edges(data=True):
        if u not in node_ids or v not in node_ids:
            continue
        edge = {"from": u, "to": v, **{k: val for k, val in data.items() if k != "relationship"}}
        edges.append(edge)
    return edges


LEGEND_HTML = """
<div id="legend" style="position:fixed; top:12px; right:12px; z-index:1000;
  background:rgba(255,255,255,0.97); border:1px solid #ccc; border-radius:8px;
  padding:12px 16px; font-family:sans-serif; font-size:13px; max-width:230px;
  box-shadow:0 2px 8px rgba(0,0,0,0.15);">
  <strong>Risk color</strong>
  <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
    background:{risk};margin-right:6px;"></span>Flagged: broad/admin access or privilege-escalation path</div>
  <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
    background:{review};margin-right:6px;"></span>Flagged: potentially unused access</div>
  <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
    background:{clean};margin-right:6px;"></span>No findings</div>
  <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
    background:{group};margin-right:6px;"></span>Group / permission</div>
  <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;
    background:{resource};margin-right:6px;"></span>Resource</div>
  <hr style="margin:8px 0;">
  <strong>Relationships</strong>
  <div><span style="display:inline-block;width:18px;height:3px;
    background:{member_of};margin-right:6px;vertical-align:middle;"></span>MEMBER_OF</div>
  <div><span style="display:inline-block;width:18px;height:3px;
    background:{has_policy};margin-right:6px;vertical-align:middle;"></span>HAS_POLICY</div>
  <div><span style="display:inline-block;width:18px;height:4px;
    background:{can_assume};margin-right:6px;vertical-align:middle;"></span>CAN_ASSUME</div>
  <div><span style="display:inline-block;width:18px;height:3px;
    background:{contains};margin-right:6px;vertical-align:middle;"></span>CONTAINS</div>
  <div><span style="display:inline-block;width:18px;height:3px;
    background:{targets};margin-right:6px;vertical-align:middle;"></span>TARGETS</div>
</div>
"""

VIEW_TOGGLE_HTML = """
<div id="view-toggle" style="position:fixed; top:12px; left:270px; z-index:1000;
  background:rgba(255,255,255,0.97); border:1px solid #ccc; border-radius:8px;
  padding:8px 10px; font-family:sans-serif; font-size:13px;
  box-shadow:0 2px 8px rgba(0,0,0,0.15);">
  <button id="btn-security" style="padding:4px 10px; margin-right:6px; cursor:pointer;">Security View</button>
  <button id="btn-full" style="padding:4px 10px; cursor:pointer;">Full Graph</button>
</div>
"""

SEARCH_HTML = """
<div id="search-box" style="position:fixed; top:12px; left:12px; z-index:1000;
  background:rgba(255,255,255,0.97); border:1px solid #ccc; border-radius:8px;
  padding:10px 14px; font-family:sans-serif; font-size:13px;
  box-shadow:0 2px 8px rgba(0,0,0,0.15);">
  <input id="node-search" type="text" placeholder="Find a user, role, or policy"
    style="width:230px; padding:4px 6px;" autocomplete="off">
  <div id="search-results" style="margin-top:6px; max-height:160px; overflow-y:auto;"></div>
</div>
"""

CAPTION_HTML = """
<div id="caption" style="position:fixed; bottom:12px; left:12px; z-index:1000;
  background:rgba(255,255,255,0.97); border:1px solid #ccc; border-radius:8px;
  padding:8px 14px; font-family:sans-serif; font-size:12px; max-width:560px;
  box-shadow:0 2px 8px rgba(0,0,0,0.15); color:#333;">
  <span id="caption-text"></span>
</div>
"""

VIEW_SCRIPT = """
<script type="text/javascript">
  var securityNodesData = {security_nodes};
  var securityEdgesData = {security_edges};
  var fullNodesData = {full_nodes};
  var fullEdgesData = {full_edges};
  var currentNodes, currentEdges;

  function showSecurityView() {{
    currentNodes = new vis.DataSet(securityNodesData);
    currentEdges = new vis.DataSet(securityEdgesData);
    network.setData({{nodes: currentNodes, edges: currentEdges}});
    document.getElementById("btn-security").style.fontWeight = "bold";
    document.getElementById("btn-full").style.fontWeight = "normal";
    document.getElementById("caption-text").textContent =
      "Security View — " + securityNodesData.length + " of " + fullNodesData.length +
      " nodes shown. AWS service-linked roles and unrelated permission/resource " +
      "detail are hidden here; switch to Full Graph to see everything.";
  }}

  function showFullGraph() {{
    currentNodes = new vis.DataSet(fullNodesData);
    currentEdges = new vis.DataSet(fullEdgesData);
    network.setData({{nodes: currentNodes, edges: currentEdges}});
    document.getElementById("btn-full").style.fontWeight = "bold";
    document.getElementById("btn-security").style.fontWeight = "normal";
    document.getElementById("caption-text").textContent =
      "Full Graph — all " + fullNodesData.length + " nodes and " + fullEdgesData.length + " edges.";
  }}

  function wireSearch() {{
    var input = document.getElementById("node-search");
    var results = document.getElementById("search-results");
    input.addEventListener("input", function () {{
      var term = input.value.trim().toLowerCase();
      results.innerHTML = "";
      if (!term) {{ return; }}
      var matches = currentNodes.get().filter(function (n) {{
        return (n.label && n.label.toLowerCase().indexOf(term) !== -1);
      }}).slice(0, 15);
      matches.forEach(function (n) {{
        var row = document.createElement("div");
        row.textContent = n.label + "  (" + n.group + ")";
        row.style.cursor = "pointer";
        row.style.padding = "2px 0";
        row.onclick = function () {{
          network.selectNodes([n.id]);
          network.focus(n.id, {{ scale: 1.6, animation: true }});
        }};
        results.appendChild(row);
      }});
    }});
  }}

  window.addEventListener("load", function () {{
    document.getElementById("btn-security").addEventListener("click", showSecurityView);
    document.getElementById("btn-full").addEventListener("click", showFullGraph);
    wireSearch();
    showSecurityView();
  }});
</script>
"""


def _legend_html() -> str:
    return LEGEND_HTML.format(
        risk=RISK_COLOR,
        review=REVIEW_COLOR,
        clean=CLEAN_COLOR,
        group=GROUP_COLOR,
        resource=RESOURCE_COLOR,
        member_of=EDGE_COLORS["MEMBER_OF"],
        has_policy=EDGE_COLORS["HAS_POLICY"],
        can_assume=EDGE_COLORS["CAN_ASSUME"],
        contains=EDGE_COLORS["CONTAINS"],
        targets=EDGE_COLORS["TARGETS"],
    )


def render_graph(graph: nx.DiGraph, findings: list[dict], output_path: Path) -> Path:
    """Render the toggleable HTML view (Security View / Full Graph); operates on styled copies only."""
    styled = _style_copy(graph, findings)
    security_ids = _security_view_node_ids(graph, findings)
    full_ids = set(styled.nodes)

    security_nodes = _to_vis_nodes(styled, security_ids)
    security_edges = _to_vis_edges(styled, security_ids)
    full_nodes = _to_vis_nodes(styled, full_ids)
    full_edges = _to_vis_edges(styled, full_ids)

    net = Network(height="850px", width="100%", directed=True, cdn_resources="in_line", bgcolor="#ffffff")
    net.from_nx(styled)
    net.set_options(
        """
        {
          "physics": {"stabilization": {"iterations": 200}},
          "interaction": {"hover": true, "dragNodes": true, "zoomView": true, "dragView": true}
        }
        """
    )

    body = net.generate_html(notebook=False)
    view_script = VIEW_SCRIPT.format(
        security_nodes=json.dumps(security_nodes),
        security_edges=json.dumps(security_edges),
        full_nodes=json.dumps(full_nodes),
        full_edges=json.dumps(full_edges),
    )
    injected = f"{_legend_html()}{VIEW_TOGGLE_HTML}{SEARCH_HTML}{CAPTION_HTML}{view_script}"
    body = body.replace("</body>", f"{injected}</body>")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(body, encoding="utf-8")
    return output_path
