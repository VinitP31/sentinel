"""indirect_privilege_path tests.

Requires >=2 CAN_ASSUME hops ending at a role holding Action=*, Resource=*.
Lives outside rules.py because it needs the resolved graph, not raw grants.
"""

import copy
import json
from pathlib import Path

import pytest

from src.analysis.indirect_privilege_path import INDIRECT_PRIVILEGE_PATH, find_indirect_privilege_paths
from src.graph.build import build_graph
from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE = Path(__file__).parent / "fixtures" / "raw_iam_authorization_details.json"


@pytest.fixture
def raw():
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def normalized(raw):
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


@pytest.fixture
def findings(graph, normalized):
    return find_indirect_privilege_paths(graph, normalized)


def test_alice_developer_admin_path_detected(findings):
    alice_findings = [f for f in findings if f["principal"]["name"] == "alice"]
    assert len(alice_findings) == 1
    finding = alice_findings[0]
    assert finding["rule"] == INDIRECT_PRIVILEGE_PATH
    assert "alice -> DeveloperRole -> AdminRole" in finding["detail"]


def test_developer_role_itself_not_flagged_single_hop(findings):
    # DeveloperRole -> AdminRole is only 1 hop from DeveloperRole itself —
    # below the 2-hop minimum for "indirect".
    assert [f for f in findings if f["principal"]["name"] == "DeveloperRole"] == []


def test_bob_and_charlie_have_no_path(findings):
    assert [f for f in findings if f["principal"]["name"] == "bob"] == []
    assert [f for f in findings if f["principal"]["name"] == "charlie"] == []


def test_finding_schema_has_no_evidence_window(findings):
    for finding in findings:
        assert set(finding.keys()) == {"rule", "principal", "policy_id", "attribution", "detail"}


def test_broken_trust_chain_produces_no_finding(raw):
    # If AdminRole's trust policy does not name DeveloperRole, the second hop
    # never exists in the graph, and the finding must not appear — not appear
    # with a gap papered over.
    broken_raw = copy.deepcopy(raw)
    for role in broken_raw["RoleDetailList"]:
        if role["RoleName"] == "AdminRole":
            role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = (
                "arn:aws:iam::123456789012:user/someone-else"
            )

    broken_normalized = resolve_group_inheritance(normalize(broken_raw))
    broken_graph = build_graph(broken_normalized)
    broken_findings = find_indirect_privilege_paths(broken_graph, broken_normalized)

    assert broken_findings == []
