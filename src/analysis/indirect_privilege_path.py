"""Indirect privilege path — the one rule deferred from Stage 6.

Requires the graph's resolved CAN_ASSUME edges (Stage 7), since it depends on
role-assumption chains that grant+trust checking alone (not a raw permission
grant) can establish. Reuses Stage 6's effective-access helpers rather than
reimplementing wildcard/Deny matching a third time.
"""

import networkx as nx

from src.analysis.rules import (
    _attribution,
    _effective_allows,
    _index_by_id,
    _is_full_wildcard,
    _permissions_by_policy,
    _principal,
)
from src.graph.build import CAN_ASSUME

INDIRECT_PRIVILEGE_PATH = "indirect_privilege_path"

MIN_HOPS = 2


def _can_assume_subgraph(graph: nx.DiGraph) -> nx.DiGraph:
    edges = [(u, v) for u, v, data in graph.edges(data=True) if data.get("relationship") == CAN_ASSUME]
    subgraph = nx.DiGraph()
    subgraph.add_nodes_from(graph.nodes)
    subgraph.add_edges_from(edges)
    return subgraph


def _terminal_admin_grant(normalized: dict, role_id: str) -> tuple[dict, dict] | tuple[None, None]:
    """The first policy/attachment on this role granting Action=*, Resource=*."""
    policy_by_id = _index_by_id(normalized["policies"])
    permissions_by_policy = _permissions_by_policy(normalized["permissions"])

    for attachment in normalized["attachments"]:
        if attachment["principal_id"] != role_id:
            continue
        policy = policy_by_id[attachment["policy_id"]]
        for permission in _effective_allows(permissions_by_policy.get(policy["id"], [])):
            if _is_full_wildcard(permission):
                return policy, attachment
    return None, None


def find_indirect_privilege_paths(graph: nx.DiGraph, normalized: dict) -> list[dict]:
    """Find CAN_ASSUME chains of at least MIN_HOPS reaching an administrative role.

    A finding fires only when every hop in the chain already satisfies
    CAN_ASSUME's grant+trust requirement — the graph, not this rule, is what
    guarantees that. If the graph is missing an edge, the path simply will
    not exist here, matching CLAUDE.md's framing that a wrong graph means a
    finding fails to appear rather than appearing incorrectly.
    """
    identity_by_id = _index_by_id(normalized["users"] + normalized["groups"] + normalized["roles"])
    assumable_principals = normalized["users"] + normalized["roles"]
    can_assume_graph = _can_assume_subgraph(graph)

    findings = []
    for principal in assumable_principals:
        if principal["id"] not in can_assume_graph:
            continue

        for target_role_id in nx.descendants(can_assume_graph, principal["id"]):
            path = nx.shortest_path(can_assume_graph, principal["id"], target_role_id)
            if len(path) - 1 < MIN_HOPS:
                continue

            policy, attachment = _terminal_admin_grant(normalized, target_role_id)
            if policy is None:
                continue

            path_names = " -> ".join(identity_by_id[node_id]["name"] for node_id in path)
            findings.append(
                {
                    "rule": INDIRECT_PRIVILEGE_PATH,
                    "principal": _principal(identity_by_id, principal["id"]),
                    "policy_id": policy["id"],
                    "attribution": _attribution(attachment),
                    "detail": (
                        f"{path_names} reaches administrative access (Action=*, Resource=*) "
                        f"via {policy['name']}."
                    ),
                }
            )

    return findings
