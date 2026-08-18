"""Demo graph visualization tests: Security View / Full Graph toggle.

Renders from the already-built graph and already-computed findings — no new
relationships invented, no AWS calls, graph.json/graph/findings never
mutated. Security View hides AWS service-linked-role branches and
non-risk-related permission/resource detail; Full Graph restores everything.
"""

import copy
import json
import re
from pathlib import Path

import pytest

from src.analysis import rules
from src.analysis.indirect_privilege_path import find_indirect_privilege_paths
from src.graph.build import build_graph
from src.graph.visualize import render_graph
from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE_DIR = Path(__file__).parent / "fixtures"

SERVICE_LINKED_ROLE_NAME = "AWSServiceRoleForTrustedAdvisor"


@pytest.fixture
def normalized():
    raw = json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())
    normalized = resolve_group_inheritance(normalize(raw))

    # This fixture predates the service-linked-role scenario — add one so
    # the exclusion behavior has something real to filter.
    normalized["roles"].append(
        {
            "provider": "aws",
            "type": "role",
            "id": "arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/" + SERVICE_LINKED_ROLE_NAME,
            "name": SERVICE_LINKED_ROLE_NAME,
            "arn": "arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/" + SERVICE_LINKED_ROLE_NAME,
            "created_at": "2026-01-01T00:00:00+00:00",
            "trust_policy": {"Version": "2012-10-17", "Statement": []},
        }
    )
    normalized["policies"].append(
        {
            "provider": "aws",
            "type": "policy",
            "id": "arn:aws:iam::aws:policy/aws-service-role/TrustedAdvisorServiceRolePolicy",
            "name": "TrustedAdvisorServiceRolePolicy",
            "arn": "arn:aws:iam::aws:policy/aws-service-role/TrustedAdvisorServiceRolePolicy",
            "policy_type": "managed",
            "document": None,
        }
    )
    normalized["permissions"].append(
        {
            "policy_id": "arn:aws:iam::aws:policy/aws-service-role/TrustedAdvisorServiceRolePolicy",
            "effect": "Allow",
            "actions": ["trustedadvisor:Describe*"],
            "resources": ["*"],
        }
    )
    normalized["attachments"].append(
        {
            "principal_id": "arn:aws:iam::123456789012:role/aws-service-role/x.amazonaws.com/"
            + SERVICE_LINKED_ROLE_NAME,
            "policy_id": "arn:aws:iam::aws:policy/aws-service-role/TrustedAdvisorServiceRolePolicy",
            "attachment_type": "direct_attached",
        }
    )
    return normalized


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


@pytest.fixture
def last_accessed():
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


@pytest.fixture
def findings(normalized, graph, last_accessed):
    found = rules.run_all(normalized, last_accessed, {"events": []})
    found += find_indirect_privilege_paths(graph, normalized)
    return found


def id_of(records, name):
    return next(r for r in records if r["name"] == name)["id"]


def _extract_js_array(content: str, var_name: str) -> list:
    match = re.search(rf"var {var_name} = (\[.*?\]);", content, re.DOTALL)
    assert match, f"could not find {var_name} in rendered HTML"
    return json.loads(match.group(1))


def test_graph_json_unmodified_by_rendering(graph, findings, tmp_path):
    before_nodes = copy.deepcopy(dict(graph.nodes(data=True)))
    before_edges = copy.deepcopy([(u, v, d) for u, v, d in graph.edges(data=True)])

    render_graph(graph, findings, tmp_path / "graph.html")

    assert dict(graph.nodes(data=True)) == before_nodes
    assert [(u, v, d) for u, v, d in graph.edges(data=True)] == before_edges


def test_html_is_generated(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    assert output.exists()
    assert output.stat().st_size > 0


def test_service_linked_role_excluded_from_security_view(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_nodes = _extract_js_array(content, "securityNodesData")
    labels = {n["label"] for n in security_nodes}
    assert SERVICE_LINKED_ROLE_NAME not in labels


def test_service_linked_role_present_in_full_graph(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    full_nodes = _extract_js_array(content, "fullNodesData")
    labels = {n["label"] for n in full_nodes}
    assert SERVICE_LINKED_ROLE_NAME in labels


def test_alice_developer_admin_path_in_security_view(graph, normalized, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_nodes = {n["id"] for n in _extract_js_array(content, "securityNodesData")}
    security_edges = _extract_js_array(content, "securityEdgesData")

    alice_id = id_of(normalized["users"], "alice")
    dev_role_id = id_of(normalized["roles"], "DeveloperRole")
    admin_role_id = id_of(normalized["roles"], "AdminRole")

    assert {alice_id, dev_role_id, admin_role_id} <= security_nodes
    pairs = {(e["from"], e["to"]) for e in security_edges}
    assert (alice_id, dev_role_id) in pairs
    assert (dev_role_id, admin_role_id) in pairs


def test_admin_policy_wildcard_chain_visible_in_security_view(graph, normalized, findings, tmp_path):
    # The headline example: AdminRole -> HAS_POLICY -> POC-Admin-Access
    # -> CONTAINS -> Allow * -> TARGETS -> *
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_nodes = _extract_js_array(content, "securityNodesData")
    labels = {n.get("label") for n in security_nodes}
    ids = {n["id"] for n in security_nodes}

    admin_policy_id = id_of(normalized["policies"], "POC-Admin-Access")
    assert admin_policy_id in ids
    assert "*" in ids  # the wildcard resource node
    assert any("Allow" in (label or "") for label in labels)


def test_alice_cannot_assume_untrusted_role(graph, normalized, findings, tmp_path):
    alice_id = id_of(normalized["users"], "alice")
    untrusted_role_id = id_of(normalized["roles"], "UntrustedRole")
    assert not graph.has_edge(alice_id, untrusted_role_id)

    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    for dataset_name in ("securityEdgesData", "fullEdgesData"):
        edges = _extract_js_array(content, dataset_name)
        pairs = {(e["from"], e["to"]) for e in edges}
        assert (alice_id, untrusted_role_id) not in pairs


def test_bob_group_inherited_relationship_visible(graph, normalized, findings, tmp_path):
    bob_id = id_of(normalized["users"], "bob")
    auditors_id = id_of(normalized["groups"], "Auditors")
    s3_policy_id = id_of(normalized["policies"], "POC-Developer-S3-ReadOnly")

    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_nodes = {n["id"] for n in _extract_js_array(content, "securityNodesData")}
    security_edges = _extract_js_array(content, "securityEdgesData")

    assert {bob_id, auditors_id, s3_policy_id} <= security_nodes
    pairs = {(e["from"], e["to"]) for e in security_edges}
    assert (bob_id, auditors_id) in pairs
    assert (bob_id, s3_policy_id) in pairs

    bob_to_policy_edge = next(e for e in security_edges if e["from"] == bob_id and e["to"] == s3_policy_id)
    assert bob_to_policy_edge.get("attachment_type") == "group_inherited"
    assert bob_to_policy_edge.get("source_group_name") == "Auditors"


def test_charlie_direct_policy_relationship_visible(graph, normalized, findings, tmp_path):
    charlie_id = id_of(normalized["users"], "charlie")
    s3_policy_id = id_of(normalized["policies"], "POC-Developer-S3-ReadOnly")

    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_edges = _extract_js_array(content, "securityEdgesData")
    pairs = {(e["from"], e["to"]): e for e in security_edges}
    assert (charlie_id, s3_policy_id) in pairs
    assert pairs[(charlie_id, s3_policy_id)].get("attachment_type") == "direct_attached"


def test_search_wiring_present_and_shared_across_views(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    assert "wireSearch" in content
    assert "currentNodes.get()" in content
    assert "showSecurityView" in content
    assert "showFullGraph" in content
    assert 'id="btn-security"' in content
    assert 'id="btn-full"' in content


def test_security_view_is_default_on_load(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    assert "showSecurityView();" in content
    load_section = content[content.index("window.addEventListener(\"load\""):]
    assert load_section.index("showSecurityView()") < load_section.index("</script>")


def test_security_view_has_fewer_nodes_than_full_graph(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    security_nodes = _extract_js_array(content, "securityNodesData")
    full_nodes = _extract_js_array(content, "fullNodesData")
    assert len(security_nodes) < len(full_nodes)


def test_no_has_role_edge_anywhere(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    for dataset_name in ("securityEdgesData", "fullEdgesData"):
        edges = _extract_js_array(content, dataset_name)
        assert all(e.get("relationship") != "HAS_ROLE" for e in edges)


def test_html_is_self_contained_vis_library(graph, findings, tmp_path):
    output = render_graph(graph, findings, tmp_path / "graph.html")
    content = output.read_text()
    assert "vis.Network" in content
