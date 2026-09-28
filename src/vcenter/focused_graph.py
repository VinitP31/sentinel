# vCenter focused relationship graphs.
"""Focused relationship graphs for the vCenter report's dedicated
Relationship Views section (never scattered throughout every finding, and
never the full inventory-wide graph src/graph/build.py produces - see
src/vcenter/report.py).

Each finding (src/vcenter/findings.py) can have many principals sharing the
identical role and set of affected entities (e.g. six service accounts all
inheriting the same Admin grant from the same root entity). Generating one
graph per principal in that case would just repeat the same picture six
times, so principals are grouped by (role, scope signature) first - one
graph per genuinely distinct pattern, labeled with how many principals share
it - before any rendering happens.

Rendering is a small, static, deterministic node-and-edge diagram (colored
dots, arrows, a legend) drawn with Pillow (already an installed dependency
of reportlab) rather than an interactive JS graph - the same rendering
embeds in both the HTML report (as a base64 PNG) and the PDF report (as a
reportlab Image). Node/edge colors deliberately match src/graph/
visualize.py's AWS graph palette so both connectors' reports read as one
Sentinel product, not two different visual systems.
"""

import math
from io import BytesIO

import networkx as nx
from PIL import Image, ImageDraw, ImageFont

ASSIGNED_ROLE = "ASSIGNED_ROLE"
CONTAINS_PRIVILEGE = "CONTAINS_PRIVILEGE"
APPLIES_TO = "APPLIES_TO"

# A No Access assignment is a deny, not a grant - the principal->role edge
# for that one finding type uses this relationship instead of ASSIGNED_ROLE,
# and the role node itself is colored distinctly (DENY_COLOR, not the usual
# structural gray) so the diagram reads as a restriction at a glance, not
# just another privilege grant. No new nodes are added for this - same
# principal/role/entity shape build_finding_graph already produces.
NO_ACCESS_OVERRIDE = "NO_ACCESS_OVERRIDE"

# A role's full privilege list can be large (the built-in Admin role has
# hundreds); above this size the focused graph omits privilege nodes
# entirely rather than becoming unreadable.
MAX_GRAPH_PRIVILEGE_NODES = 6

# A finding's affected-entity list can also be long (one real grant visible
# via inheritance at many descendant entities); above this size only the
# first few get their own node, the rest collapse into one "+N more" node.
MAX_ENTITY_NODES = 3

# A finding can group many principals under one rule (e.g. every Admin
# holder); above this size only the first few get their own node, the rest
# collapse into one "+N more principals" node - the same pattern already
# used for entities above.
MAX_PRINCIPAL_GRAPH_NODES = 10

NODE_RADIUS = {"principal": 11, "role": 13, "privilege": 8, "entity": 11}
ROW_GAP = 46
COLUMN_GAP = 210
PADDING = 40
LEGEND_HEIGHT = 108

# Node/edge colors intentionally match src/graph/visualize.py's palette
# (RISK_COLOR/REVIEW_COLOR/CLEAN_COLOR/GROUP_COLOR/RESOURCE_COLOR and
# EDGE_COLORS) so a vCenter relationship graph reads as the same Sentinel
# product as the AWS one, not a different visual system. Duplicated here
# rather than imported - focused_graph.py has no reason to depend on
# src/graph/visualize.py (which pulls in pyvis, an HTML-graph dependency
# unrelated to this static-PNG renderer) just to share four hex constants.
RISK_COLOR = "#DE350B"
REVIEW_COLOR = "#FFAB00"
CLEAN_COLOR = "#36B37E"
STRUCTURAL_COLOR = "#8993A4"  # role / privilege - matches AWS's "Group/permission" gray
ENTITY_COLOR = "#E8547A"  # matches AWS's "Resource" pink

# No AWS equivalent exists for a deny/override role (AWS has no No Access
# construct) - a new color, not a reuse of RISK_COLOR, so it never collides
# with the "High-risk principal" legend meaning within the same diagram.
DENY_COLOR = "#5243AA"

EDGE_COLORS = {
    ASSIGNED_ROLE: "#4C9AFF",  # matches AWS's HAS_POLICY blue
    CONTAINS_PRIVILEGE: "#36B37E",  # matches AWS's CONTAINS green
    APPLIES_TO: "#E8547A",  # matches AWS's TARGETS pink
    NO_ACCESS_OVERRIDE: DENY_COLOR,
}

BORDER_COLOR = "#42526E"
TEXT_COLOR = "#172B4D"
EDGE_LABEL_COLOR = "#6B778C"
LABEL_BG_COLOR = "#FFFFFF"


def _scope_signature(assignments: list[dict]) -> tuple:
    return tuple(sorted((a["entity_id"], a["attachment_type"]) for a in assignments))


def group_principals_by_pattern(principals: list[dict]) -> list[dict]:
    """principals sharing the identical (role, affected-entity-set) pattern
    collapse into one group - this is what keeps the Relationship Views
    section from showing visually identical graphs for principals that
    only differ by name."""
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for entry in principals:
        key = (entry["role"]["id"], _scope_signature(entry["assignments"]))
        if key not in groups:
            groups[key] = {
                "role": entry["role"],
                "privileges": entry["privileges"],
                "assignments": entry["assignments"],
                "principal_names": [],
            }
            order.append(key)
        groups[key]["principal_names"].append(entry["principal"]["name"])
    return [groups[key] for key in order]


def build_focused_graph(principal_label: str, role: dict, privileges: list[str], assignments: list[dict]) -> nx.DiGraph:
    """Principal(s) -> Role -> [Privilege ...] -> Entity (or entities),
    built only from the fields already given - never invents a relationship
    beyond what is passed in."""
    graph = nx.DiGraph()

    principal_node = "principal:0"
    role_node = f"role:{role['id']}"

    graph.add_node(principal_node, label=principal_label, kind="principal")
    graph.add_node(role_node, label=role["name"], kind="role")
    graph.add_edge(principal_node, role_node, relationship=ASSIGNED_ROLE)

    last_node = role_node
    if len(privileges) <= MAX_GRAPH_PRIVILEGE_NODES:
        for privilege_id in privileges:
            privilege_node = f"privilege:{privilege_id}"
            graph.add_node(privilege_node, label=privilege_id, kind="privilege")
            graph.add_edge(last_node, privilege_node, relationship=CONTAINS_PRIVILEGE)
            last_node = privilege_node

    shown = assignments[:MAX_ENTITY_NODES]
    for assignment in shown:
        entity_node = f"entity:{assignment['entity_id']}"
        label = assignment["entity_name"] or assignment["entity_id"]
        suffix = "" if assignment["attachment_type"] == "vcenter_direct" else " (inherited)"
        graph.add_node(entity_node, label=label + suffix, kind="entity")
        graph.add_edge(last_node, entity_node, relationship=APPLIES_TO)

    remaining = len(assignments) - len(shown)
    if remaining > 0:
        more_node = "entity:__more__"
        graph.add_node(more_node, label=f"+{remaining} more entit{'y' if remaining == 1 else 'ies'}", kind="entity")
        graph.add_edge(last_node, more_node, relationship=APPLIES_TO)

    return graph


def _font(size: int = 13) -> ImageFont.ImageFont:
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # older Pillow: load_default() takes no size argument
        return ImageFont.load_default()


def _node_fill_color(kind: str, severity: str | None) -> str:
    if kind == "principal":
        return RISK_COLOR if severity == "high" else REVIEW_COLOR if severity == "medium" else CLEAN_COLOR
    if kind == "entity":
        return ENTITY_COLOR
    return STRUCTURAL_COLOR  # role / privilege


def _shorten_for_graph(label: str, max_len: int = 40) -> str:
    return label if len(label) <= max_len else label[: max_len - 3] + "..."


def _short_principal_label(name: str, max_len: int = 22) -> str:
    """Graph-only display label - strips a leading DOMAIN\\ prefix (every
    principal in one diagram usually shares the same domain, so repeating
    it seven times over adds width without adding information) and
    truncates if the remainder is still long. Never used for the report's
    tables, which always keep the full principal name."""
    local = name.split("\\")[-1]
    return _shorten_for_graph(local, max_len)


def _text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return right - left, bottom - top


def render_focused_graph_png(graph: nx.DiGraph) -> bytes:
    """Render a clean node-and-edge relationship diagram: small colored dots
    (never rectangles) with a text label above each, arrows between them,
    and a legend explaining every color and relationship used - the same
    visual language as the AWS Sentinel report's relationship graphs (see
    module docstring for the shared palette). Deterministic: the same graph
    always produces the same image.

    Every graph this module builds is layered by construction - principal
    node(s), then a role node, then a linear chain of privilege nodes, then
    entity node(s) - never entity-to-entity or principal-to-principal
    edges. Nodes of the same kind that fan in/out (multiple principals,
    multiple entities) are laid out side by side in their own row so a
    fanned edge is a straight line to the one box it actually names, never
    drawn through an unrelated box in between.

    A graph can contain more than one such layered chain (build_finding_graph
    now groups principals by their own role - see its docstring), so each
    weakly-connected component gets its own column, placed side by side.
    Interleaving two unrelated chains into one shared column previously
    drew an edge crossing through another role's unrelated privilege node -
    a real rendering bug once a finding could span more than one role, not
    a stylistic choice.
    """
    font = _font()

    # A node's on-canvas footprint is whichever is wider: its dot or its
    # label - a long label must never overhang the canvas edge or its
    # neighbor, which a fixed dot-diameter spacing does not guarantee.
    _measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    labels = {n: _shorten_for_graph(str(graph.nodes[n].get("label", n))) for n in graph.nodes}
    footprints = {
        n: max(NODE_RADIUS.get(graph.nodes[n].get("kind", ""), 11) * 2, _text_size(_measure, labels[n], font)[0] + 10)
        for n in graph.nodes
    }
    ROW_ITEM_GAP = 26
    COMPONENT_GAP = 50

    def _row_width(nodes: list[str]) -> int:
        return sum(footprints[n] for n in nodes) + max(0, len(nodes) - 1) * ROW_ITEM_GAP

    components = [sorted(component) for component in nx.weakly_connected_components(graph)]
    components.sort()  # deterministic left-to-right order regardless of set iteration order

    component_layouts = []
    for component in components:
        component_set = set(component)
        principal_nodes = [n for n in component if graph.nodes[n].get("kind") == "principal"]
        entity_nodes = [n for n in component if graph.nodes[n].get("kind") == "entity"]
        # chain_nodes (role, then a linear sequence of privileges) are
        # stacked one per row, never combined side by side - only
        # principal/entity fan rows can contain more than one node.
        chain_nodes = [
            n
            for n in nx.topological_sort(graph.subgraph(component_set))
            if graph.nodes[n].get("kind") not in ("principal", "entity")
        ]
        rows: list[list[str]] = []
        if principal_nodes:
            rows.append(principal_nodes)
        rows.extend([n] for n in chain_nodes)
        if entity_nodes:
            rows.append(entity_nodes)
        width = max(_row_width(principal_nodes), _row_width(entity_nodes), max((footprints[n] for n in component), default=0), 1)
        component_layouts.append({"rows": rows, "width": width})

    row_height = ROW_GAP + max(NODE_RADIUS.values()) * 2
    max_rows = max((len(c["rows"]) for c in component_layouts), default=0)
    content_width = sum(c["width"] for c in component_layouts) + max(0, len(component_layouts) - 1) * COMPONENT_GAP
    canvas_width = max(content_width, 360) + PADDING * 2
    height = PADDING * 2 + max_rows * row_height + LEGEND_HEIGHT

    image = Image.new("RGB", (canvas_width, height), "white")
    draw = ImageDraw.Draw(image)

    positions: dict[str, tuple[float, float]] = {}  # node -> (center_x, center_y)

    def _place_row(nodes: list[str], y: float, center_x: float) -> None:
        if not nodes:
            return
        total_width = _row_width(nodes)
        x = center_x - total_width / 2
        for node in nodes:
            width = footprints[node]
            positions[node] = (x + width / 2, y)
            x += width + ROW_ITEM_GAP

    x_cursor = PADDING
    for component in component_layouts:
        component_center_x = x_cursor + component["width"] / 2
        y = PADDING + max(NODE_RADIUS.values())
        for row in component["rows"]:
            _place_row(row, y, component_center_x)
            y += row_height
        x_cursor += component["width"] + COMPONENT_GAP

    def _draw_node(node: str) -> None:
        kind = graph.nodes[node].get("kind", "")
        severity = graph.nodes[node].get("severity")
        radius = NODE_RADIUS.get(kind, 11)
        cx, cy = positions[node]
        color = DENY_COLOR if graph.nodes[node].get("deny") else _node_fill_color(kind, severity)
        draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], fill=color, outline=BORDER_COLOR, width=2)

        label = labels[node]
        text_w, text_h = _text_size(draw, label, font)
        label_x = cx - text_w / 2
        label_y = cy - radius - text_h - 6
        draw.rectangle([label_x - 3, label_y - 1, label_x + text_w + 3, label_y + text_h + 1], fill=LABEL_BG_COLOR)
        draw.text((label_x, label_y), label, fill=TEXT_COLOR, font=font)

    def _draw_edge(source: str, target: str, relationship: str) -> None:
        sx, sy = positions[source]
        tx, ty = positions[target]
        s_radius = NODE_RADIUS.get(graph.nodes[source].get("kind", ""), 11)
        t_radius = NODE_RADIUS.get(graph.nodes[target].get("kind", ""), 11)
        angle = math.atan2(ty - sy, tx - sx)
        start = (sx + s_radius * math.cos(angle), sy + s_radius * math.sin(angle))
        end = (tx - t_radius * math.cos(angle), ty - t_radius * math.sin(angle))
        color = EDGE_COLORS.get(relationship, BORDER_COLOR)
        draw.line([start, end], fill=color, width=2)
        back = math.pi
        tip = end
        left = (tip[0] + 7 * math.cos(angle + back - 0.4), tip[1] + 7 * math.sin(angle + back - 0.4))
        right = (tip[0] + 7 * math.cos(angle + back + 0.4), tip[1] + 7 * math.sin(angle + back + 0.4))
        draw.polygon([tip, left, right], fill=color)

    for source, target, data in graph.edges(data=True):
        _draw_edge(source, target, str(data.get("relationship", "")))
    for node in graph.nodes:
        _draw_node(node)

    _draw_legend(draw, font, graph, canvas_width, height - LEGEND_HEIGHT + 10)

    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


_LEGEND_NODE_ITEMS = (
    (RISK_COLOR, "High-risk principal"),
    (REVIEW_COLOR, "Review-risk principal"),
    (STRUCTURAL_COLOR, "Role / privilege"),
    (ENTITY_COLOR, "Entity (scope)"),
    (DENY_COLOR, "No Access / deny role"),
)
_LEGEND_EDGE_ITEMS = (
    (EDGE_COLORS[ASSIGNED_ROLE], ASSIGNED_ROLE),
    (EDGE_COLORS[CONTAINS_PRIVILEGE], CONTAINS_PRIVILEGE),
    (EDGE_COLORS[APPLIES_TO], APPLIES_TO),
    (EDGE_COLORS[NO_ACCESS_OVERRIDE], NO_ACCESS_OVERRIDE),
)


def _draw_legend(draw: ImageDraw.ImageDraw, font: ImageFont.ImageFont, graph: nx.DiGraph, canvas_width: int, top: float) -> None:
    """A small legend box explaining every node color and edge type
    actually used in this diagram - only rows relevant to this specific
    graph are shown, never the full fixed set regardless of content."""
    kinds_present = {graph.nodes[n].get("kind") for n in graph.nodes}
    severities_present = {graph.nodes[n].get("severity") for n in graph.nodes if graph.nodes[n].get("kind") == "principal"}
    deny_present = any(graph.nodes[n].get("deny") for n in graph.nodes)
    relationships_present = {str(data.get("relationship", "")) for _u, _v, data in graph.edges(data=True)}

    node_rows = []
    if "high" in severities_present:
        node_rows.append(_LEGEND_NODE_ITEMS[0])
    if "medium" in severities_present or "low" in severities_present:
        node_rows.append(_LEGEND_NODE_ITEMS[1])
    if kinds_present & {"role", "privilege"}:
        node_rows.append(_LEGEND_NODE_ITEMS[2])
    if "entity" in kinds_present:
        node_rows.append(_LEGEND_NODE_ITEMS[3])
    if deny_present:
        node_rows.append(_LEGEND_NODE_ITEMS[4])
    edge_rows = [item for item in _LEGEND_EDGE_ITEMS if item[1] in relationships_present]

    box_left = PADDING
    box_right = canvas_width - PADDING
    box_top = top
    row_height = 20
    box_bottom = box_top + 14 + row_height * max(len(node_rows), len(edge_rows))
    draw.rectangle([box_left, box_top, box_right, box_bottom], fill="#FAFBFC", outline="#DFE1E6")

    col2_x = box_left + (box_right - box_left) // 2
    for i, (color, label) in enumerate(node_rows):
        y = box_top + 10 + i * row_height
        draw.ellipse([box_left + 12, y + 3, box_left + 22, y + 13], fill=color, outline=BORDER_COLOR)
        draw.text((box_left + 30, y), label, fill=TEXT_COLOR, font=font)
    for i, (color, label) in enumerate(edge_rows):
        y = box_top + 10 + i * row_height
        draw.line([(col2_x + 12, y + 8), (col2_x + 32, y + 8)], fill=color, width=3)
        draw.text((col2_x + 40, y), label, fill=TEXT_COLOR, font=font)


def build_relationship_views(finding: dict) -> list[dict]:
    """One view per distinct (role, affected-entity-set) pattern in this
    finding - each view is {"label", "principal_names", "graph"}. A finding
    with 7 principals all sharing the identical Admin grant produces one
    view, not seven. Available for callers that want per-pattern detail;
    the report's Relationship Views section uses build_finding_graph below
    instead, which targets exactly one diagram per finding type."""
    groups = group_principals_by_pattern(finding["principals"])
    views = []
    for group in groups:
        names = group["principal_names"]
        label = names[0] if len(names) == 1 else f"{group['role']['name']} - {len(names)} principals"
        graph = build_focused_graph(label, group["role"], group["privileges"], group["assignments"])
        views.append({"label": label, "principal_names": names, "graph": graph})
    return views


def build_finding_graph(finding: dict, deny: bool = False) -> dict:
    """Exactly one relationship view for an entire finding - not one per
    principal, and not one per role/scope pattern within it. The report's
    Relationship Views section targets exactly one diagram per finding type.

    Unlike build_focused_graph (a single principal_label string), every
    actually affected principal gets its own node fanning into its role - a
    security reviewer must see who is affected, not just a count (capped at
    MAX_PRINCIPAL_GRAPH_NODES per role, the same "+N more" pattern already
    used for entities, so a 50-principal finding still renders instead of
    becoming unreadable).

    Principals are grouped by their own role first, not assumed to share
    one. VCENTER-ADMIN-001 and VCENTER-AUTH-001 happen to always produce
    exactly one group (every matching principal really does share the
    identical role, by construction - see src/vcenter/findings.py), so
    those render exactly as before. VCENTER-PRIV-001 can genuinely span
    several different roles that each independently contain one of the
    high-impact privileges (e.g. DangerousRole, VsmSvcRole, vCLSAdmin all
    matched for different principals in the real sandbox) - collapsing
    that into one shared role node would show a privilege chain the role
    node's own label never actually grants, which is exactly the kind of
    unsupported claim this project does not allow. Each role's privileges
    and affected entities are scoped to that role's own principals only,
    never mixed across roles.

    deny: True only for the No Access Override finding - a deny is not a
    grant, so the principal->role edge uses NO_ACCESS_OVERRIDE instead of
    ASSIGNED_ROLE, and the role node itself is colored as a deny (see
    _draw_node). No new nodes are added either way - same shape, different
    relationship/color on the exact same nodes.
    """
    principals = finding["principals"]
    names = [p["principal"]["name"] for p in principals]
    severity = finding.get("severity", "low")
    role_relationship = NO_ACCESS_OVERRIDE if deny else ASSIGNED_ROLE

    role_order: list[str] = []
    principals_by_role: dict[str, list[dict]] = {}
    roles_by_id: dict[str, dict] = {}
    for entry in principals:
        role_id = entry["role"]["id"]
        if role_id not in principals_by_role:
            principals_by_role[role_id] = []
            roles_by_id[role_id] = entry["role"]
            role_order.append(role_id)
        principals_by_role[role_id].append(entry)

    graph = nx.DiGraph()
    for role_id in role_order:
        role = roles_by_id[role_id]
        role_entries = principals_by_role[role_id]
        role_node = f"role:{role_id}"
        graph.add_node(role_node, label=role["name"], kind="role", deny=deny)

        shown_principals = role_entries[:MAX_PRINCIPAL_GRAPH_NODES]
        for entry in shown_principals:
            node = f"principal:{entry['principal']['id']}"
            graph.add_node(node, label=_short_principal_label(entry["principal"]["name"]), kind="principal", severity=severity)
            graph.add_edge(node, role_node, relationship=role_relationship)
        remaining_principals = len(role_entries) - len(shown_principals)
        if remaining_principals > 0:
            more_node = f"principal:__more__:{role_id}"
            label = f"+{remaining_principals} more principal{'s' if remaining_principals != 1 else ''}"
            graph.add_node(more_node, label=label, kind="principal", severity=severity)
            graph.add_edge(more_node, role_node, relationship=role_relationship)

        last_node = role_node
        role_privileges = role_entries[0]["privileges"]
        if len(role_privileges) <= MAX_GRAPH_PRIVILEGE_NODES:
            for privilege_id in role_privileges:
                privilege_node = f"privilege:{role_id}:{privilege_id}"
                graph.add_node(privilege_node, label=privilege_id, kind="privilege")
                graph.add_edge(last_node, privilege_node, relationship=CONTAINS_PRIVILEGE)
                last_node = privilege_node

        seen_entities: dict[str, dict] = {}
        for entry in role_entries:
            for assignment in entry["assignments"]:
                seen_entities.setdefault(assignment["entity_id"], assignment)
        assignments = sorted(seen_entities.values(), key=lambda a: a["entity_name"] or a["entity_id"])

        shown_entities = assignments[:MAX_ENTITY_NODES]
        for assignment in shown_entities:
            entity_node = f"entity:{role_id}:{assignment['entity_id']}"
            label = assignment["entity_name"] or assignment["entity_id"]
            suffix = "" if assignment["attachment_type"] == "vcenter_direct" else " (inherited)"
            graph.add_node(entity_node, label=label + suffix, kind="entity")
            graph.add_edge(last_node, entity_node, relationship=APPLIES_TO)
        remaining_entities = len(assignments) - len(shown_entities)
        if remaining_entities > 0:
            more_node = f"entity:__more__:{role_id}"
            label = f"+{remaining_entities} more entit{'y' if remaining_entities == 1 else 'ies'}"
            graph.add_node(more_node, label=label, kind="entity")
            graph.add_edge(last_node, more_node, relationship=APPLIES_TO)

    return {"label": finding["title"], "principal_names": names, "graph": graph}
