"""Normalize vCenter inventory + authorization collector output into the
same common model src/normalize/iam.py produces for AWS.

Input: inventory_collector.collect()'s data dict and
authorization_collector.collect()'s data dict (not the CollectionStatus
tuples - callers handle status separately, same convention as
src/normalize/iam.py::normalize(raw_iam)).

Mapping (see src/vcenter/CLAUDE.md Phase 6 for the full design rationale):
- permission.principal + permission.group -> a synthesized users/groups
  identity record (vCenter has no separate "list all principals" API; the
  principal string itself is the only identity fact available).
- role -> policy (roleId -> policy id, str; role.system -> policy_type
  "system"/"custom"; role name -> policy name).
- role's privilege ids (via role_privileges) -> one permission record per
  role, actions = privilege ids, effect always "Allow" (vCenter roles have
  no per-privilege Allow/Deny), resources = every distinct entity_id that
  role was observed bound to across the collected entities.
- each individual permission occurrence -> one attachment record, carrying
  the additive entity_id/entity_type/propagate fields and an
  attachment_type of "vcenter_direct" or "vcenter_inherited" (never
  collapsed together - the collector already tells them apart).

Deliberately NOT done here (unresolved, see src/vcenter/CLAUDE.md):
- vCenter's built-in Admin role is NOT converted to actions=["*"] - its
  actual privilege ids are preserved as collected.
- No Access (roleId=-5) is NOT given any override/Deny semantics - if it
  appears, it is normalized like any other role, nothing more.
- No group membership is fabricated - `memberships` is always [].
- No effective-access computation of any kind.
"""

PROVIDER = "vcenter"


def _synthesize_principal(principal: str, is_group: bool) -> dict:
    return {
        "provider": PROVIDER,
        "type": "group" if is_group else "user",
        "id": principal,
        "name": principal,
        "arn": None,
        "created_at": None,
    }


def _build_principals(entity_permissions: list[dict]) -> tuple[list[dict], list[dict]]:
    """One record per distinct principal string, deduplicated.

    First observation of a principal wins; the same principal appearing as
    both group=True and group=False somewhere else would be a genuine data
    anomaly this doesn't try to resolve, only avoid duplicating.
    """
    seen: dict[str, dict] = {}
    for entity in entity_permissions:
        for permission in entity["all"]:
            principal = permission["principal"]
            if principal not in seen:
                seen[principal] = _synthesize_principal(principal, permission["group"])

    users = [record for record in seen.values() if record["type"] == "user"]
    groups = [record for record in seen.values() if record["type"] == "group"]
    return users, groups


def _entity_names(inventory: dict) -> dict[str, str]:
    """id -> name, from whatever inventory the caller already collected.
    Absent if the entity isn't in the inventory data - never invented."""
    names: dict[str, str] = {}
    for records in inventory.values():
        for record in records:
            entity_id = record.get("id")
            if entity_id is not None:
                names[entity_id] = record.get("name")
    return names


def _policy_id(role_id: int, entity_id: str) -> str:
    """A vCenter role carries no resource scope of its own - the same role
    can be bound to many different entities for many different principals.
    Giving every (role, entity) binding its own policy id keeps the graph's
    policy -> permission -> resource edges scoped to only the entity that
    binding actually applies to.

    Sharing one policy id (and therefore one permission/resource node) across
    every binding of a role was tried first and proven wrong: graph traversal
    from a principal bound to that role at one entity could structurally
    reach every OTHER entity that same role happened to be bound to for a
    completely different principal (see tests/test_vcenter_pipeline_compatibility.py
    and src/vcenter/CLAUDE.md for the specific case this was caught against).
    """
    return f"{role_id}@{entity_id}"


def _build_policies_and_permissions(
    roles: dict, role_privileges: dict, entity_permissions: list[dict]
) -> tuple[list[dict], list[dict]]:
    """One policy + one permission record per (role, entity) binding actually
    observed, scoped by _policy_id - plus one unscoped baseline policy (bare
    str(role_id), resources=[]) for any collected role never observed bound
    to anything, so every role fetched from roleList is still preserved as a
    fact even when nothing currently attaches to it.
    """
    bindings: set[tuple[int, str]] = set()
    for entity in entity_permissions:
        for permission in entity["all"]:
            bindings.add((permission["roleId"], permission["entity_id"]))
    bound_role_ids = {role_id for role_id, _entity_id in bindings}

    policies = []
    permissions = []

    def _add(role_id: int, role: dict, policy_id: str, resources: list[str]) -> None:
        policies.append(
            {
                "provider": PROVIDER,
                "type": "policy",
                "id": policy_id,
                "name": role["name"],
                "arn": None,
                "policy_type": "system" if role["system"] else "custom",
                "document": None,
            }
        )
        actions = [privilege["privId"] for privilege in role_privileges.get(role_id, [])]
        permissions.append({"policy_id": policy_id, "effect": "Allow", "actions": actions, "resources": resources})

    for role_id, entity_id in sorted(bindings):
        _add(role_id, roles[role_id], _policy_id(role_id, entity_id), [entity_id])

    for role_id, role in roles.items():
        if role_id not in bound_role_ids:
            _add(role_id, role, str(role_id), [])

    return policies, permissions


def _attachment_record(permission: dict, attachment_type: str, entity_names: dict[str, str]) -> dict:
    return {
        "principal_id": permission["principal"],
        "policy_id": _policy_id(permission["roleId"], permission["entity_id"]),
        "attachment_type": attachment_type,
        "entity_id": permission["entity_id"],
        "entity_type": permission["entity_type"],
        "entity_name": entity_names.get(permission["entity_id"]),
        "propagate": permission["propagate"],
    }


def _attachment_identity(record: dict) -> tuple:
    """Identity deliberately excludes attachment_type: a permission actually
    defined at entity E is the same real-world fact whether it was
    discovered by querying E directly (attachment_type="vcenter_direct") or
    by querying a descendant of E, whose "inherited" list reports it with
    the SAME entity_id=E (an inherited permission's entity_id always names
    where it is actually defined, never the entity being queried - see
    src/vcenter/CLAUDE.md Phase 5). Treating those as two different
    attachments would count entity E itself as "one additional entity via
    inheritance" - not a real additional entity, just the same one seen
    twice through two discovery paths."""
    return (record["principal_id"], record["policy_id"], record["entity_id"])


def _build_attachments(entity_permissions: list[dict], entity_names: dict[str, str]) -> list[dict]:
    """One attachment per distinct (principal, policy, entity) fact.

    Deduplication is required, not optional, for two separate reasons, both
    confirmed against the real vCenter sandbox:

    1. An inherited permission's entity_id is always the entity where it is
       actually defined (e.g. the root), not the entity being queried.
       Since authorization_collector queries every entity in the inventory,
       the same root-level grant is rediscovered once per descendant entity
       that inherits it - without this dedup, a single real fact ("Admin at
       root, inherited everywhere") was counted as up to 20 separate
       "affected entities" in one real run, none of which were actually
       distinct entities.
    2. The entity where a permission is directly defined is ALSO reported
       in some descendant's "inherited" list under the identical entity_id
       (see _attachment_identity docstring) - if not collapsed, that same
       single entity is counted twice under two different attachment_type
       labels, appearing as a phantom "1 additional entity via inheritance"
       that is not actually a different entity.

    When both a direct and an inherited sighting exist for the same
    (principal, policy, entity), direct wins - the permission genuinely is
    defined there, so that is the correct classification, not "inherited".
    """
    seen: dict[tuple, dict] = {}
    for entity in entity_permissions:
        for permission in entity["direct"]:
            record = _attachment_record(permission, "vcenter_direct", entity_names)
            seen[_attachment_identity(record)] = record  # direct always wins, even over an already-seen inherited sighting
        for permission in entity["inherited"]:
            record = _attachment_record(permission, "vcenter_inherited", entity_names)
            seen.setdefault(_attachment_identity(record), record)
    return list(seen.values())


def normalize(inventory: dict, authorization: dict) -> dict:
    """vCenter inventory + authorization -> the common model.

    Returns the same seven keys src/normalize/iam.py::normalize() produces.
    `roles` is always [] - vCenter has no assumable-role principal concept,
    unlike AWS IAM roles. `memberships` is always [] - group membership is
    not collected, so it is never fabricated.
    """
    entity_permissions = authorization.get("entity_permissions", [])
    roles = authorization.get("roles", {})
    role_privileges = authorization.get("role_privileges", {})

    users, groups = _build_principals(entity_permissions)
    policies, permissions = _build_policies_and_permissions(roles, role_privileges, entity_permissions)
    entity_names = _entity_names(inventory)
    attachments = _build_attachments(entity_permissions, entity_names)

    return {
        "users": users,
        "groups": groups,
        "roles": [],
        "policies": policies,
        "permissions": permissions,
        "attachments": attachments,
        "memberships": [],
    }
