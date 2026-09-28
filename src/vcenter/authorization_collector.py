# vCenter authorization collection.
"""vCenter authorization collection.

Collects roles, privileges, and per-entity permissions via
AuthorizationManager (src/vcenter/soap_client.py's VCenterSoapClient).
Read-only: `roleList`/`privilegeList` are documented data properties;
`RetrieveEntityPermissions` is a documented query operation requiring only
System.Read (src/vcenter/CLAUDE.md section 7). No mutating call exists
anywhere in this module.

Direct-vs-inherited is derived by diffing RetrieveEntityPermissions(entity,
False) against RetrieveEntityPermissions(entity, True) - the permission
object itself carries no "inherited" flag. This was empirically confirmed
against the real sandbox in the Phase 5 investigation (see
src/vcenter/CLAUDE.md), not assumed from documentation alone.

Explicitly NOT implemented here, per the same investigation:
- group membership resolution - the permission API does not expose it.
- No Access override / effective-access computation - the observed roleId
  is preserved as-is if it appears; nothing is computed on top of it.
- any other speculative effective-access resolution the API does not
  itself state.
"""

from pyVmomi import vim

from src.util.status import CollectionStatus, failed, ok
from src.vcenter.soap_client import VCenterSoapClient, VCenterSoapError

SOURCE = "vcenter_authorization"

# inventory_collector's object_type label -> pyVmomi managed-object type.
# Mirrors exactly the six types src.vcenter.inventory_collector produces -
# nothing here assumes a type inventory doesn't already emit.
_ENTITY_TYPES = {
    "datacenter": vim.Datacenter,
    "folder": vim.Folder,
    "cluster": vim.ClusterComputeResource,
    "host": vim.HostSystem,
    "vm": vim.VirtualMachine,
    "resource_pool": vim.ResourcePool,
}


def _entity_ref(client: VCenterSoapClient, object_type: str, object_id: str):
    vim_type = _ENTITY_TYPES.get(object_type)
    if vim_type is None:
        raise ValueError(f"no pyVmomi type mapping for inventory object_type {object_type!r}")
    return vim_type(object_id, client.service_instance._stub)


def collect_roles(client: VCenterSoapClient) -> dict[int, dict]:
    """roleId -> {roleId, name, system, label, privilege_ids}.

    role.privilege is a list of privilege ID strings, not privilege objects
    (observed against the real sandbox) - kept as IDs here; resolution to
    privilege detail is a separate step (resolve_role_privileges).
    """
    try:
        roles = client.content.authorizationManager.roleList
    except Exception as exc:
        raise VCenterSoapError(f"roleList failed: {exc}") from exc

    return {
        role.roleId: {
            "roleId": role.roleId,
            "name": role.name,
            "system": role.system,
            "label": role.info.label if role.info else None,
            "privilege_ids": list(role.privilege) if role.privilege else [],
        }
        for role in roles
    }


def collect_privileges(client: VCenterSoapClient) -> dict[str, dict]:
    """privId -> {privId, name, group_name, on_parent}."""
    try:
        privileges = client.content.authorizationManager.privilegeList
    except Exception as exc:
        raise VCenterSoapError(f"privilegeList failed: {exc}") from exc

    return {
        priv.privId: {
            "privId": priv.privId,
            "name": priv.name,
            "group_name": priv.privGroupName,
            "on_parent": priv.onParent,
        }
        for priv in privileges
    }


def resolve_role_privileges(roles_by_id: dict, privileges_by_id: dict, role_id: int) -> list[dict]:
    """roleId -> role -> privilege ids -> privilege details.

    An unknown role id returns an empty list rather than raising. An
    unknown privilege id (a privilege referenced by a role but absent from
    privilegeList) is preserved as a partial record with the id and no
    other detail, rather than silently dropped - both are fatcs the
    collector should surface, not hide.
    """
    role = roles_by_id.get(role_id)
    if role is None:
        return []

    resolved = []
    for priv_id in role["privilege_ids"]:
        privilege = privileges_by_id.get(priv_id)
        if privilege is not None:
            resolved.append(privilege)
        else:
            resolved.append({"privId": priv_id, "name": None, "group_name": None, "on_parent": None})
    return resolved


def _permission_record(permission, roles_by_id: dict) -> dict:
    entity = permission.entity
    role = roles_by_id.get(permission.roleId)
    return {
        "principal": permission.principal,
        "group": permission.group,
        "roleId": permission.roleId,
        "role_name": role["name"] if role else None,
        "propagate": permission.propagate,
        "entity_type": type(entity).__name__,
        "entity_id": entity._moId,
    }


def _permission_identity(record: dict) -> tuple:
    """Stable identity used only to diff direct vs. inherited result sets -
    not a vCenter-issued id (the API assigns none to a permission)."""
    return (record["principal"], record["roleId"], record["entity_type"], record["entity_id"])


def collect_entity_permissions(client: VCenterSoapClient, object_type: str, object_id: str, roles_by_id: dict) -> dict:
    """Direct + inherited permissions for one inventory entity.

    Calls RetrieveEntityPermissions twice (inherited=False, inherited=True)
    and derives the direct/inherited split by diffing the two - the API
    itself never labels a permission as direct or inherited.
    """
    entity = _entity_ref(client, object_type, object_id)
    auth_manager = client.content.authorizationManager

    try:
        direct_raw = auth_manager.RetrieveEntityPermissions(entity, False)
        all_raw = auth_manager.RetrieveEntityPermissions(entity, True)
    except Exception as exc:
        raise VCenterSoapError(f"RetrieveEntityPermissions failed for {object_type} {object_id}: {exc}") from exc

    direct = [_permission_record(p, roles_by_id) for p in direct_raw]
    all_permissions = [_permission_record(p, roles_by_id) for p in all_raw]

    direct_identities = {_permission_identity(r) for r in direct}
    inherited = [r for r in all_permissions if _permission_identity(r) not in direct_identities]

    return {
        "entity_type": object_type,
        "entity_id": object_id,
        "direct": direct,
        "inherited": inherited,
        "all": all_permissions,
    }


def collect(client: VCenterSoapClient, entities: list[dict]) -> tuple[dict, CollectionStatus]:
    """Collect roles, privileges, and per-entity permissions.

    entities: records shaped like src.vcenter.inventory_collector's output
    ({"type": ..., "id": ..., ...} - extra keys ignored).

    Computes no effective access, no group membership, no No Access
    override - only preserves what AuthorizationManager actually returns,
    plus the derived direct/inherited split and role/privilege resolution.
    """
    try:
        roles_by_id = collect_roles(client)
        privileges_by_id = collect_privileges(client)
    except VCenterSoapError as exc:
        return {}, failed(SOURCE, str(exc))

    role_privileges = {
        role_id: resolve_role_privileges(roles_by_id, privileges_by_id, role_id) for role_id in roles_by_id
    }

    entity_permissions = []
    for entity in entities:
        try:
            entity_permissions.append(
                collect_entity_permissions(client, entity["type"], entity["id"], roles_by_id)
            )
        except VCenterSoapError as exc:
            return {}, failed(SOURCE, str(exc))

    counts = {
        "roles": len(roles_by_id),
        "privileges": len(privileges_by_id),
        "entities": len(entity_permissions),
    }

    return (
        {
            "roles": roles_by_id,
            "privileges": privileges_by_id,
            "role_privileges": role_privileges,
            "entity_permissions": entity_permissions,
        },
        ok(SOURCE, counts),
    )
