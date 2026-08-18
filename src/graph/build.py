"""Build the relationship graph from normalized IAM data.

Knows nothing about AWS — consumes only the common model produced by
src/normalize/. Establishes nodes and relationships only; does not decide
whether anything is a security problem (that is src/analysis/). Must not
import from src/analysis/ — CAN_ASSUME resolution needs a small amount of
wildcard/Deny-matching logic, duplicated here in minimal form rather than
importing Stage 6's rules module, to keep the layers independent.

Never emits a HAS_ROLE edge — the relationship is Principal -> CAN_ASSUME ->
Role, and only when both a permission grant and the target role's trust
policy agree.
"""

import fnmatch

import networkx as nx

MEMBER_OF = "MEMBER_OF"
HAS_POLICY = "HAS_POLICY"
CONTAINS = "CONTAINS"
TARGETS = "TARGETS"
CAN_ASSUME = "CAN_ASSUME"

ASSUME_ROLE_ACTION = "sts:AssumeRole"


def _patterns_cover(covering_patterns: list[str], covered_patterns: list[str]) -> bool:
    """True if every pattern in `covered_patterns` is matched by some pattern in `covering_patterns`."""
    for covered in covered_patterns:
        if not any(fnmatch.fnmatchcase(covered, covering) for covering in covering_patterns):
            return False
    return True


def _is_denied(policy_permissions: list[dict], allow_permission: dict) -> bool:
    for other in policy_permissions:
        if other["effect"] != "Deny":
            continue
        if _patterns_cover(other["actions"], allow_permission["actions"]) and _patterns_cover(
            other["resources"], allow_permission["resources"]
        ):
            return True
    return False


def _permission_node_id(policy_id: str, index: int) -> str:
    return f"{policy_id}#permission-{index}"


def _permissions_by_policy(permissions: list[dict]) -> dict[str, list[dict]]:
    by_policy: dict[str, list[dict]] = {}
    for permission in permissions:
        by_policy.setdefault(permission["policy_id"], []).append(permission)
    return by_policy


def _trusted_principal_arns(trust_policy: dict) -> set[str]:
    """ARNs a role's trust policy allows to assume it via sts:AssumeRole."""
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    trusted: set[str] = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(fnmatch.fnmatchcase(ASSUME_ROLE_ACTION, action) for action in actions):
            continue

        principal = statement.get("Principal", {})
        aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        trusted.update(aws_principals)

    return trusted


def _grants_assume_role(policy_permissions: list[dict], role_arn: str) -> bool:
    """True if an effective (non-denied) Allow in these permissions covers sts:AssumeRole on role_arn."""
    for permission in policy_permissions:
        if permission["effect"] != "Allow":
            continue
        if not any(fnmatch.fnmatchcase(ASSUME_ROLE_ACTION, action) for action in permission["actions"]):
            continue
        if not any(fnmatch.fnmatchcase(role_arn, resource) for resource in permission["resources"]):
            continue
        if _is_denied(policy_permissions, permission):
            continue
        return True
    return False


def build_graph(normalized: dict) -> nx.DiGraph:
    graph = nx.DiGraph()
    permissions_by_policy = _permissions_by_policy(normalized["permissions"])

    for kind in ("users", "groups", "roles"):
        for record in normalized[kind]:
            graph.add_node(record["id"], node_type=record["type"], name=record["name"])

    for policy in normalized["policies"]:
        graph.add_node(policy["id"], node_type="policy", name=policy["name"], policy_type=policy["policy_type"])

    for policy_id, permissions in permissions_by_policy.items():
        for index, permission in enumerate(permissions):
            permission_node = _permission_node_id(policy_id, index)
            graph.add_node(
                permission_node,
                node_type="permission",
                effect=permission["effect"],
                actions=permission["actions"],
            )
            # CONTAINS is deliberately effect-neutral — Deny permissions are
            # included exactly like Allow, never filtered out.
            graph.add_edge(policy_id, permission_node, relationship=CONTAINS)

            for resource in permission["resources"]:
                # A resource string can be another entity's own ARN (e.g. an
                # sts:AssumeRole permission's resource is the target role).
                # Never clobber an already-known node's real type/name with
                # the generic "resource" classification.
                if resource not in graph:
                    graph.add_node(resource, node_type="resource")
                graph.add_edge(permission_node, resource, relationship=TARGETS)

    for membership in normalized["memberships"]:
        graph.add_edge(membership["user_id"], membership["group_id"], relationship=MEMBER_OF)

    for attachment in normalized["attachments"]:
        graph.add_edge(
            attachment["principal_id"],
            attachment["policy_id"],
            relationship=HAS_POLICY,
            attachment_type=attachment["attachment_type"],
            source_group_name=attachment.get("source_group_name"),
        )

    attachments_by_principal: dict[str, list[dict]] = {}
    for attachment in normalized["attachments"]:
        attachments_by_principal.setdefault(attachment["principal_id"], []).append(attachment)

    # Deny precedence is checked within a single policy's own permissions,
    # matching Stage 6's same-policy scoping (POC.md's planted test case is
    # itself a single-policy Allow+Deny pair) — a Deny in one attached policy
    # is not treated as overriding an Allow granted by a different policy.
    assumable_principals = normalized["users"] + normalized["roles"]
    for role in normalized["roles"]:
        trusted_arns = _trusted_principal_arns(role["trust_policy"])
        if not trusted_arns:
            continue
        for principal in assumable_principals:
            if principal["id"] not in trusted_arns:
                continue
            principal_attachments = attachments_by_principal.get(principal["id"], [])
            grants = any(
                _grants_assume_role(permissions_by_policy.get(attachment["policy_id"], []), role["id"])
                for attachment in principal_attachments
            )
            if grants:
                graph.add_edge(principal["id"], role["id"], relationship=CAN_ASSUME)

    return graph
