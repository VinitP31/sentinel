"""vCenter focused relationship graph tests. No network, no real vCenter."""

from src.vcenter.focused_graph import (
    APPLIES_TO,
    ASSIGNED_ROLE,
    CONTAINS_PRIVILEGE,
    MAX_ENTITY_NODES,
    MAX_GRAPH_PRIVILEGE_NODES,
    MAX_PRINCIPAL_GRAPH_NODES,
    NO_ACCESS_OVERRIDE,
    build_finding_graph,
    build_focused_graph,
    build_relationship_views,
    group_principals_by_pattern,
    render_focused_graph_png,
)


def make_assignment(entity_id="group-d1", entity_name="Datacenters", attachment_type="vcenter_direct"):
    return {"entity_id": entity_id, "entity_type": "folder", "entity_name": entity_name, "propagate": True, "attachment_type": attachment_type}


def make_principal_entry(principal_id, role_id="-1", role_name="Admin", privileges=None, assignments=None):
    return {
        "principal": {"id": principal_id, "name": principal_id, "type": "user"},
        "role": {"id": role_id, "name": role_name, "system": True},
        "privileges": privileges if privileges is not None else ["Authorization.ModifyPermissions"],
        "assignments": assignments if assignments is not None else [make_assignment()],
        "assignments_summary": "Datacenters (direct)",
    }


def test_build_focused_graph_has_only_relevant_nodes():
    graph = build_focused_graph("someone", {"id": "-1", "name": "Admin"}, ["Authorization.ModifyPermissions"], [make_assignment()])
    assert set(graph.nodes) == {"principal:0", "role:-1", "privilege:Authorization.ModifyPermissions", "entity:group-d1"}
    assert graph.number_of_edges() == 3


def test_build_focused_graph_edge_labels_match_spec():
    graph = build_focused_graph("someone", {"id": "-1", "name": "Admin"}, ["Authorization.ModifyPermissions"], [make_assignment()])
    relationships = {data["relationship"] for _u, _v, data in graph.edges(data=True)}
    assert relationships == {ASSIGNED_ROLE, CONTAINS_PRIVILEGE, APPLIES_TO}


def test_build_focused_graph_omits_privilege_nodes_when_too_many():
    many_privileges = [f"System.Priv{i}" for i in range(MAX_GRAPH_PRIVILEGE_NODES + 5)]
    graph = build_focused_graph("someone", {"id": "-1", "name": "Admin"}, many_privileges, [make_assignment()])
    assert set(graph.nodes) == {"principal:0", "role:-1", "entity:group-d1"}
    assert graph.number_of_edges() == 2


def test_build_focused_graph_collapses_many_entities():
    assignments = [make_assignment(entity_id=f"e{i}", entity_name=f"Entity{i}") for i in range(10)]
    graph = build_focused_graph("someone", {"id": "-1", "name": "Admin"}, [], assignments)
    entity_nodes = [n for n, data in graph.nodes(data=True) if data.get("kind") == "entity"]
    assert len(entity_nodes) == MAX_ENTITY_NODES + 1


def test_render_focused_graph_png_produces_valid_png_bytes():
    graph = build_focused_graph("someone", {"id": "-1", "name": "Admin"}, ["Authorization.ModifyPermissions"], [make_assignment()])
    png_bytes = render_focused_graph_png(graph)
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


# --- grouping / dedup ---

def test_group_principals_by_pattern_merges_identical_role_and_scope():
    """Six principals with the same role and the same set of affected
    entities must collapse to one group, not six visually identical ones."""
    shared_assignments = [make_assignment()]
    principals = [make_principal_entry(f"user{i}", assignments=shared_assignments) for i in range(6)]

    groups = group_principals_by_pattern(principals)

    assert len(groups) == 1
    assert len(groups[0]["principal_names"]) == 6


def test_group_principals_by_pattern_keeps_distinct_scopes_separate():
    principals = [
        make_principal_entry("user1", assignments=[make_assignment(entity_id="group-d1", entity_name="Datacenters")]),
        make_principal_entry("user2", assignments=[make_assignment(entity_id="group-x9", entity_name="DC-Lab")]),
    ]
    groups = group_principals_by_pattern(principals)
    assert len(groups) == 2


def test_group_principals_by_pattern_keeps_distinct_roles_separate():
    principals = [
        make_principal_entry("user1", role_id="-1", role_name="Admin"),
        make_principal_entry("user2", role_id="579378617", role_name="ConnectorReaderPlus"),
    ]
    groups = group_principals_by_pattern(principals)
    assert len(groups) == 2


def test_build_relationship_views_produces_one_view_per_distinct_pattern():
    """A finding with 6 identical-pattern principals and 1 different one
    must produce exactly 2 relationship views, not 7."""
    shared_assignments = [make_assignment()]
    principals = [make_principal_entry(f"user{i}", assignments=shared_assignments) for i in range(6)]
    principals.append(make_principal_entry("dev-alice", assignments=[make_assignment(entity_id="dc-lab", entity_name="DC-Lab")]))
    finding = {"principals": principals}

    views = build_relationship_views(finding)

    assert len(views) == 2
    shared_view = next(v for v in views if len(v["principal_names"]) == 6)
    assert "Admin" in shared_view["label"]
    assert "6 principals" in shared_view["label"]


def test_build_relationship_views_renders_valid_png_for_each_view():
    principals = [make_principal_entry("user1")]
    finding = {"principals": principals}
    views = build_relationship_views(finding)
    png_bytes = render_focused_graph_png(views[0]["graph"])
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


# --- build_finding_graph: the graph report.py actually renders --------------


def make_finding(principals, title="Administrative Access", severity="high"):
    return {"title": title, "severity": severity, "principals": principals}


def test_build_finding_graph_single_role_fans_every_principal_into_one_role_node():
    """VCENTER-ADMIN-001/-AUTH-001's real shape: every principal shares the
    identical role - one role node, everyone fans into it."""
    principals = [
        make_principal_entry("Administrator", privileges=["System.Read"]),
        make_principal_entry("dev-alice", privileges=["System.Read"]),
    ]
    view = build_finding_graph(make_finding(principals))
    graph = view["graph"]
    role_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "role"]
    assert role_nodes == ["role:-1"]
    assert graph.in_degree("role:-1") == 2


def test_build_finding_graph_multi_role_creates_one_role_node_per_distinct_role():
    """VCENTER-PRIV-001's real shape: principals can hold different roles
    that each independently contain a matched privilege - each must get its
    own role node and its own privilege chain, never one shared role node
    claiming a privilege a different role actually has."""
    principals = [
        make_principal_entry("platform-admins", role_id="-405023589", role_name="DangerousRole", privileges=["Global.Settings", "Sessions.TerminateSession"]),
        make_principal_entry("vmware-vsm-1", role_id="1034", role_name="VsmSvcRole", privileges=["Sessions.TerminateSession"]),
    ]
    view = build_finding_graph(make_finding(principals, title="High-Impact Privilege Access"))
    graph = view["graph"]

    role_nodes = {n for n, d in graph.nodes(data=True) if d.get("kind") == "role"}
    assert role_nodes == {"role:-405023589", "role:1034"}

    import networkx as nx

    dangerous_privileges = {n for n in nx.descendants(graph, "role:-405023589") if graph.nodes[n].get("kind") == "privilege"}
    vsm_privileges = {n for n in nx.descendants(graph, "role:1034") if graph.nodes[n].get("kind") == "privilege"}
    assert dangerous_privileges == {"privilege:-405023589:Global.Settings", "privilege:-405023589:Sessions.TerminateSession"}
    assert vsm_privileges == {"privilege:1034:Sessions.TerminateSession"}
    # VsmSvcRole must never appear to grant Global.Settings - it never had it
    assert "privilege:1034:Global.Settings" not in graph.nodes

    # each role is fed only by the principal that actually holds it
    assert list(graph.predecessors("role:-405023589")) == ["principal:platform-admins"]
    assert list(graph.predecessors("role:1034")) == ["principal:vmware-vsm-1"]


def test_build_finding_graph_multi_role_renders_without_crossing_into_one_column():
    """Regression guard: the two role chains must land in separate weakly
    connected components, not interleaved into a single chain (the bug this
    graph rewrite fixed)."""
    import networkx as nx

    principals = [
        make_principal_entry("platform-admins", role_id="-405023589", role_name="DangerousRole", privileges=["Global.Settings"]),
        make_principal_entry("vmware-vsm-1", role_id="1034", role_name="VsmSvcRole", privileges=["Sessions.TerminateSession"]),
    ]
    view = build_finding_graph(make_finding(principals, title="High-Impact Privilege Access"))
    components = list(nx.weakly_connected_components(view["graph"]))
    assert len(components) == 2


def test_build_finding_graph_deny_uses_no_access_override_relationship():
    principals = [make_principal_entry("ReadOnlyUsers", role_id="-5", role_name="NoAccess", privileges=[])]
    view = build_finding_graph(make_finding(principals, title="No Access Override", severity="medium"), deny=True)
    graph = view["graph"]
    relationships = {data["relationship"] for _u, _v, data in graph.edges(data=True) if graph.nodes[_v].get("kind") == "role"}
    assert relationships == {NO_ACCESS_OVERRIDE}
    assert graph.nodes["role:-5"]["deny"] is True


def test_build_finding_graph_non_deny_uses_assigned_role_relationship():
    principals = [make_principal_entry("Administrator", privileges=["System.Read"])]
    view = build_finding_graph(make_finding(principals))
    graph = view["graph"]
    relationships = {data["relationship"] for _u, _v, data in graph.edges(data=True) if graph.nodes[_v].get("kind") == "role"}
    assert relationships == {ASSIGNED_ROLE}
    assert graph.nodes["role:-1"].get("deny", False) is False


def test_build_finding_graph_caps_principals_per_role():
    principals = [make_principal_entry(f"user{i}") for i in range(MAX_PRINCIPAL_GRAPH_NODES + 5)]
    view = build_finding_graph(make_finding(principals))
    graph = view["graph"]
    principal_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "principal"]
    assert len(principal_nodes) == MAX_PRINCIPAL_GRAPH_NODES + 1  # +1 for the "+N more" node


def test_build_finding_graph_omits_privileges_when_a_role_has_too_many():
    many_privileges = [f"System.Priv{i}" for i in range(MAX_GRAPH_PRIVILEGE_NODES + 5)]
    principals = [make_principal_entry("Administrator", privileges=many_privileges)]
    view = build_finding_graph(make_finding(principals))
    graph = view["graph"]
    privilege_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "privilege"]
    assert privilege_nodes == []


def test_render_focused_graph_png_handles_multi_role_graph():
    principals = [
        make_principal_entry("platform-admins", role_id="-405023589", role_name="DangerousRole", privileges=["Global.Settings"]),
        make_principal_entry("vmware-vsm-1", role_id="1034", role_name="VsmSvcRole", privileges=["Sessions.TerminateSession"]),
        make_principal_entry("Administrators", role_id="-1", role_name="vCLSAdmin", privileges=["Global.Settings"]),
    ]
    view = build_finding_graph(make_finding(principals, title="High-Impact Privilege Access"))
    png_bytes = render_focused_graph_png(view["graph"])
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")


def test_render_focused_graph_png_handles_deny_graph():
    principals = [make_principal_entry("ReadOnlyUsers", role_id="-5", role_name="NoAccess", privileges=[])]
    view = build_finding_graph(make_finding(principals, title="No Access Override", severity="medium"), deny=True)
    png_bytes = render_focused_graph_png(view["graph"])
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
