"""Relationship graph construction tests.

Scope: nodes/edges only, resolved CAN_ASSUME requiring grant + trust. No
security judgement here — that's src/analysis/. The fixture's UntrustedRole
trusts bob while alice holds a grant on it — the negative test case for
CAN_ASSUME.
"""

import json
from pathlib import Path

import networkx as nx
import pytest

from src.graph.build import CAN_ASSUME, CONTAINS, HAS_POLICY, MEMBER_OF, TARGETS, build_graph
from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE = Path(__file__).parent / "fixtures" / "raw_iam_authorization_details.json"


@pytest.fixture
def normalized():
    raw = json.loads(FIXTURE.read_text())
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


def id_of(records, name):
    return next(r for r in records if r["name"] == name)["id"]


def edges_of_type(graph, relationship):
    return [(u, v) for u, v, data in graph.edges(data=True) if data.get("relationship") == relationship]


def test_alice_can_assume_developer_role(graph, normalized):
    alice_id = id_of(normalized["users"], "alice")
    dev_role_id = id_of(normalized["roles"], "DeveloperRole")
    assert graph.has_edge(alice_id, dev_role_id)
    assert graph[alice_id][dev_role_id]["relationship"] == CAN_ASSUME


def test_developer_role_can_assume_admin_role(graph, normalized):
    dev_role_id = id_of(normalized["roles"], "DeveloperRole")
    admin_role_id = id_of(normalized["roles"], "AdminRole")
    assert graph.has_edge(dev_role_id, admin_role_id)
    assert graph[dev_role_id][admin_role_id]["relationship"] == CAN_ASSUME


def test_alice_cannot_assume_untrusted_role_despite_grant(graph, normalized):
    # Alice holds POC-UntrustedRole-Assume (a real grant), but UntrustedRole's
    # trust policy names only bob. No edge must appear for alice.
    alice_id = id_of(normalized["users"], "alice")
    untrusted_role_id = id_of(normalized["roles"], "UntrustedRole")
    assert not graph.has_edge(alice_id, untrusted_role_id)


def test_no_has_role_edge_ever_created(graph):
    relationships = {data.get("relationship") for _, _, data in graph.edges(data=True)}
    assert "HAS_ROLE" not in relationships


def test_has_policy_edges_preserve_attachment_type(graph, normalized):
    charlie_id = id_of(normalized["users"], "charlie")
    s3_policy_id = id_of(normalized["policies"], "POC-Developer-S3-ReadOnly")
    assert graph[charlie_id][s3_policy_id]["attachment_type"] == "direct_attached"

    bob_id = id_of(normalized["users"], "bob")
    assert graph[bob_id][s3_policy_id]["attachment_type"] == "group_inherited"
    assert graph[bob_id][s3_policy_id]["source_group_name"] == "Auditors"


def test_member_of_edge_exists_for_alice_developers(graph, normalized):
    alice_id = id_of(normalized["users"], "alice")
    developers_id = id_of(normalized["groups"], "Developers")
    assert graph.has_edge(alice_id, developers_id)
    assert graph[alice_id][developers_id]["relationship"] == MEMBER_OF


def test_contains_edges_include_deny_permissions(graph, normalized):
    deny_policy_id = id_of(normalized["policies"], "POC-Auditor-IAM-Deny-Test")
    permission_nodes = [
        v for u, v in edges_of_type(graph, CONTAINS) if u == deny_policy_id
    ]
    effects = {graph.nodes[node]["effect"] for node in permission_nodes}
    assert "Deny" in effects
    assert "Allow" in effects


def test_targets_edges_point_at_resource_nodes(graph, normalized):
    s3_policy_id = id_of(normalized["policies"], "POC-Developer-S3-ReadOnly")
    permission_nodes = [v for u, v in edges_of_type(graph, CONTAINS) if u == s3_policy_id]
    resource_nodes = [v for u, v in edges_of_type(graph, TARGETS) if u in permission_nodes]
    assert any(graph.nodes[r]["node_type"] == "resource" for r in resource_nodes)
    assert "arn:aws:s3:::example-bucket/*" in resource_nodes


def test_resource_node_id_is_the_raw_resource_string(graph):
    assert graph.nodes["arn:aws:s3:::example-bucket/*"]["node_type"] == "resource"


def test_admin_role_full_wildcard_permission_node_present(graph, normalized):
    admin_role_id = id_of(normalized["roles"], "AdminRole")
    admin_policy_id = id_of(normalized["policies"], "POC-Admin-Access")
    assert graph.has_edge(admin_role_id, admin_policy_id)
    permission_nodes = [v for u, v in edges_of_type(graph, CONTAINS) if u == admin_policy_id]
    assert any(graph.nodes[p]["actions"] == ["*"] for p in permission_nodes)


def test_graph_is_json_serializable(graph):
    data = nx.node_link_data(graph)
    json.dumps(data)  # must not raise
