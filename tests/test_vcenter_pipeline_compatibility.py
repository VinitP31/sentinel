"""vCenter normalized-data compatibility with the EXISTING graph/findings/
evidence pipeline - no vCenter-specific code involved except normalize()
itself. Runs the real, unmodified src/graph/build.py, src/analysis/rules.py,
src/analysis/indirect_privilege_path.py, and src/evidence/build.py against a
normalized vCenter fixture, to prove (not assume) compatibility.

Fixture shapes match what was actually observed against the real sandbox in
Phase 5/6 (principal VSPHERE.LOCAL\\ops-carol, role ReadOnlyPlus, privilege
System.View, entity AppTeam/group-v2006) plus the real observed case of one
role (ReadOnlyPlus) bound at two different entities for two different
principals.
"""

import fnmatch

import networkx as nx
import pytest

from src.analysis import rules
from src.analysis.indirect_privilege_path import find_indirect_privilege_paths
from src.evidence.build import build_evidence_package
from src.graph.build import CAN_ASSUME, HAS_POLICY, TARGETS, build_graph
from src.vcenter.normalize import normalize


def make_inventory():
    return {
        "datacenter": [{"id": "datacenter-2001", "type": "datacenter", "name": "DC-Lab", "parent": None}],
        "folder": [
            {"id": "group-d1", "type": "folder", "name": "Datacenters", "parent": None},
            {"id": "group-v2006", "type": "folder", "name": "AppTeam", "parent": None},
        ],
        "cluster": [],
        "host": [],
        "vm": [],
    }


def make_authorization():
    """ReadOnlyPlus is bound at BOTH group-d1 (ops-carol) and group-v2006
    (ghost-user) - the real observed multi-entity-role case - plus Admin
    (system role, real privilege ids, never converted to "*") bound once."""
    return {
        "roles": {
            1148447843: {"roleId": 1148447843, "name": "ReadOnlyPlus", "system": False, "label": "ReadOnlyPlus", "privilege_ids": ["System.View"]},
            -1: {"roleId": -1, "name": "Admin", "system": True, "label": "Admin", "privilege_ids": ["System.Read", "System.Write", "Folder.Create"]},
        },
        "privileges": {
            "System.View": {"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False},
            "System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
            "System.Write": {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
            "Folder.Create": {"privId": "Folder.Create", "name": "Create Folder", "group_name": "Folder", "on_parent": False},
        },
        "role_privileges": {
            1148447843: [{"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False}],
            -1: [
                {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
                {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
                {"privId": "Folder.Create", "name": "Create Folder", "group_name": "Folder", "on_parent": False},
            ],
        },
        "entity_permissions": [
            {
                "entity_type": "folder",
                "entity_id": "group-d1",
                "direct": [
                    {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
                "inherited": [],
                "all": [
                    {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
            },
            {
                "entity_type": "folder",
                "entity_id": "group-v2006",
                "direct": [
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                    {"principal": "OKTA.CALFUS.AI\\ghost-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
                "inherited": [
                    {"principal": "OKTA.CALFUS.AI\\ghost-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
                "all": [
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                    {"principal": "OKTA.CALFUS.AI\\ghost-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
            },
        ],
    }


@pytest.fixture
def normalized():
    return normalize(make_inventory(), make_authorization())


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


# --- 1. normalized vCenter data can enter the existing graph ---
def test_graph_builds_without_error(graph):
    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0


# --- 2. principal -> role/policy relationship preserved ---
def test_principal_has_policy_edge_to_its_role(normalized, graph):
    ops_carol_id = next(u["id"] for u in normalized["users"] if u["name"] == "VSPHERE.LOCAL\\ops-carol")
    policy_edges = [v for u, v, d in graph.out_edges(ops_carol_id, data=True) if d.get("relationship") == HAS_POLICY]
    assert len(policy_edges) == 1
    assert policy_edges[0] == "1148447843@group-v2006"


# --- 3. role -> privilege relationship preserved ---
def test_policy_contains_permission_with_privilege_actions(graph):
    permission_node = "1148447843@group-v2006#permission-0"
    assert graph.nodes[permission_node]["actions"] == ["System.View"]


# --- 4. role/resource relationship preserved, entity_id survives ---
def test_permission_targets_the_correct_resource(graph):
    permission_node = "1148447843@group-v2006#permission-0"
    targets = [v for u, v, d in graph.out_edges(permission_node, data=True) if d.get("relationship") == TARGETS]
    assert targets == ["group-v2006"]


# --- 5. multiple resources for one role behave correctly / vCenter IDs do not cause accidental matches ---
def test_role_bound_at_two_entities_does_not_cross_contaminate(normalized, graph):
    ops_carol_id = next(u["id"] for u in normalized["users"] if u["name"] == "VSPHERE.LOCAL\\ops-carol")
    ghost_user_id = next(u["id"] for u in normalized["users"] if u["name"] == "OKTA.CALFUS.AI\\ghost-user")

    ops_carol_reach = nx.descendants(graph, ops_carol_id)
    ghost_user_reach = nx.descendants(graph, ghost_user_id)

    assert "group-v2006" in ops_carol_reach
    assert "group-d1" not in ops_carol_reach  # NOT ops-carol's entity

    assert "group-d1" in ghost_user_reach
    assert "group-v2006" not in ghost_user_reach  # NOT ghost-user's entity


# --- 6. relevant existing findings execute without error ---
def test_broad_permission_rule_executes_without_error(normalized):
    findings = rules.broad_permission_and_administrative_access(normalized)
    assert isinstance(findings, list)


def test_indirect_privilege_path_executes_and_finds_nothing(normalized, graph):
    # vCenter has no CAN_ASSUME-equivalent construct - this must run cleanly
    # and simply find nothing, not crash.
    assert not any(d.get("relationship") == CAN_ASSUME for _u, _v, d in graph.edges(data=True))
    findings = find_indirect_privilege_paths(graph, normalized)
    assert findings == []


def test_potentially_unused_access_executes_without_crashing_on_empty_activity(normalized):
    # Compatibility only - NOT asserting this produces a correct vCenter
    # finding. Activity is NOT_SUPPORTED for vCenter; this must be gated off
    # before Phase 8, not fed empty data as if it were a real absence signal.
    findings = rules.potentially_unused_access(normalized, {}, {})
    assert isinstance(findings, list)


def test_evidence_package_builds_without_error(normalized, graph):
    package = build_evidence_package(normalized, graph, {}, {}, {}, region="n/a")
    assert "packages" in package
    ops_carol_id = next(u["id"] for u in normalized["users"] if u["name"] == "VSPHERE.LOCAL\\ops-carol")
    assert ops_carol_id in package["packages"]


# --- 7. Administrator: does NOT trip the broad/admin rule (documented, not fixed here) ---
def test_admin_role_does_not_trigger_broad_permission_rule(normalized):
    """vCenter's Admin role keeps its real privilege ids (System.Read/
    System.Write/Folder.Create), never actions=["*"] - so the AWS rule's
    literal wildcard check does not fire. This documents the current,
    correct-per-design result; it is not a bug to fix in this phase."""
    findings = rules.broad_permission_and_administrative_access(normalized)
    admin_findings = [f for f in findings if f["principal"]["name"] == "VSPHERE.LOCAL\\Administrators"]
    assert admin_findings == []


# --- 8. fnmatch/resource matching behavior with vCenter-style entity ids ---
@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("group-v2006", True),
        ("group-v2007", False),
        ("group-*", True),
        ("unrelated-resource", False),
    ],
)
def test_fnmatch_behavior_against_vcenter_entity_ids(pattern, expected):
    assert fnmatch.fnmatchcase("group-v2006", pattern) is expected
