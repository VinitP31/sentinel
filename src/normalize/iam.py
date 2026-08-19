"""Normalize raw IAM configuration into the common model.

Covers direct/inline policy attachments and group-inherited access, added
on top of the same attachment records rather than a second permission
model. Role-assumption graph logic lives in src/graph/. This module does
not decide whether anything is a security problem — it only translates AWS
vocabulary into the common model (identities, groups, roles, policies,
permissions, attachments, memberships).
"""

from typing import Any

from src.aws.iam_collector import decode_policy_document

MANAGED = "managed"
INLINE = "inline"

DIRECT_ATTACHED = "direct_attached"
GROUP_INHERITED = "group_inherited"


def _identity(kind: str, name: str, entity_id: str, arn: str, created_at: Any) -> dict:
    return {
        "provider": "aws",
        "type": kind,
        "id": entity_id,
        "name": name,
        "arn": arn,
        "created_at": created_at,
    }


def _permissions_from_document(policy_id: str, document: dict) -> list[dict]:
    """Flatten a policy document's statements into Permission records.

    Effect, actions and resources are kept exactly as written — wildcards are
    not expanded and Deny is never dropped.
    """
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    permissions = []
    for statement in statements:
        actions = statement.get("Action", statement.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]
        resources = statement.get("Resource", statement.get("NotResource", []))
        if isinstance(resources, str):
            resources = [resources]

        permission = {
            "policy_id": policy_id,
            "effect": statement["Effect"],
            "actions": actions,
            "resources": resources,
        }
        if "Sid" in statement:
            permission["sid"] = statement["Sid"]
        if "Condition" in statement:
            permission["condition"] = statement["Condition"]
        permissions.append(permission)

    return permissions


def _managed_policy_records(raw_policies: list[dict]) -> tuple[list[dict], list[dict]]:
    """Normalize customer/AWS-managed policies (raw `Policies` section).

    Only the policy's default version document is normalized — the rest of
    the version history is not relevant access evidence.
    """
    policies = []
    permissions = []

    for raw_policy in raw_policies:
        policy_id = raw_policy["Arn"]
        default_version_id = raw_policy.get("DefaultVersionId")
        document = None
        for version in raw_policy.get("PolicyVersionList", []):
            if version.get("VersionId") == default_version_id:
                document = decode_policy_document(version["Document"])
                break

        policies.append(
            {
                "provider": "aws",
                "type": "policy",
                "id": policy_id,
                "name": raw_policy["PolicyName"],
                "arn": policy_id,
                "policy_type": MANAGED,
                "document": document,
            }
        )
        if document is not None:
            permissions.extend(_permissions_from_document(policy_id, document))

    return policies, permissions


def _inline_policy_records(owner_id: str, raw_inline_policies: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Normalize inline policies embedded on a user/role.

    Inline policies have no ARN in the AWS API — they only exist scoped to
    their owner, so the normalized id is synthesized from the owner.
    """
    policies = []
    permissions = []
    attachments = []

    for raw_inline in raw_inline_policies:
        name = raw_inline["PolicyName"]
        policy_id = f"{owner_id}:inline:{name}"
        document = decode_policy_document(raw_inline["PolicyDocument"])

        policies.append(
            {
                "provider": "aws",
                "type": "policy",
                "id": policy_id,
                "name": name,
                "arn": None,
                "policy_type": INLINE,
                "document": document,
            }
        )
        permissions.extend(_permissions_from_document(policy_id, document))
        attachments.append(
            {
                "principal_id": owner_id,
                "policy_id": policy_id,
                "attachment_type": INLINE,
            }
        )

    return policies, permissions, attachments


def _direct_attachments(owner_id: str, raw_attached_managed_policies: list[dict]) -> list[dict]:
    return [
        {
            "principal_id": owner_id,
            "policy_id": raw_attached["PolicyArn"],
            "attachment_type": DIRECT_ATTACHED,
        }
        for raw_attached in raw_attached_managed_policies
    ]


def normalize(raw: dict) -> dict:
    """Normalize users, groups, roles and their direct/inline policies.

    Returns the common-model records, keyed by type, plus user->group
    `memberships`. Does not resolve membership into inherited access —
    that is `resolve_group_inheritance`.
    """
    users = []
    groups = []
    roles = []
    policies = []
    permissions = []
    attachments = []
    memberships = []

    # Groups first: user membership resolution below needs group name -> id.
    for raw_group in raw.get("GroupDetailList", []):
        group_id = raw_group["Arn"]
        groups.append(_identity("group", raw_group["GroupName"], group_id, raw_group["Arn"], raw_group["CreateDate"]))
        attachments.extend(_direct_attachments(group_id, raw_group.get("AttachedManagedPolicies", [])))
        inline_policies, inline_permissions, inline_attachments = _inline_policy_records(
            group_id, raw_group.get("GroupPolicyList", [])
        )
        policies.extend(inline_policies)
        permissions.extend(inline_permissions)
        attachments.extend(inline_attachments)

    group_id_by_name = {g["name"]: g["id"] for g in groups}

    for raw_user in raw.get("UserDetailList", []):
        user_id = raw_user["Arn"]
        users.append(_identity("user", raw_user["UserName"], user_id, raw_user["Arn"], raw_user["CreateDate"]))
        attachments.extend(_direct_attachments(user_id, raw_user.get("AttachedManagedPolicies", [])))
        inline_policies, inline_permissions, inline_attachments = _inline_policy_records(
            user_id, raw_user.get("UserPolicyList", [])
        )
        policies.extend(inline_policies)
        permissions.extend(inline_permissions)
        attachments.extend(inline_attachments)

        for group_name in raw_user.get("GroupList", []):
            group_id = group_id_by_name.get(group_name)
            if group_id is not None:
                memberships.append({"user_id": user_id, "group_id": group_id, "group_name": group_name})

    for raw_role in raw.get("RoleDetailList", []):
        role_id = raw_role["Arn"]
        role_record = _identity("role", raw_role["RoleName"], role_id, raw_role["Arn"], raw_role["CreateDate"])
        role_record["trust_policy"] = decode_policy_document(raw_role["AssumeRolePolicyDocument"])
        roles.append(role_record)
        attachments.extend(_direct_attachments(role_id, raw_role.get("AttachedManagedPolicies", [])))
        inline_policies, inline_permissions, inline_attachments = _inline_policy_records(
            role_id, raw_role.get("RolePolicyList", [])
        )
        policies.extend(inline_policies)
        permissions.extend(inline_permissions)
        attachments.extend(inline_attachments)

    managed_policies, managed_permissions = _managed_policy_records(raw.get("Policies", []))
    policies.extend(managed_policies)
    permissions.extend(managed_permissions)

    return {
        "users": users,
        "groups": groups,
        "roles": roles,
        "policies": policies,
        "permissions": permissions,
        "attachments": attachments,
        "memberships": memberships,
    }


def resolve_group_inheritance(normalized: dict) -> dict:
    """Add group-inherited attachment records on top of the normalized model.

    These resolve against the same `policy_id`, so Deny statements and
    wildcards carry through unchanged.
    """
    inherited = []
    for membership in normalized["memberships"]:
        group_attachments = [
            a for a in normalized["attachments"] if a["principal_id"] == membership["group_id"]
        ]
        for group_attachment in group_attachments:
            inherited.append(
                {
                    "principal_id": membership["user_id"],
                    "policy_id": group_attachment["policy_id"],
                    "attachment_type": GROUP_INHERITED,
                    "source_group_id": membership["group_id"],
                    "source_group_name": membership["group_name"],
                }
            )

    return {**normalized, "attachments": normalized["attachments"] + inherited}
