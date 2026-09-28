"""vCenter authorization collector tests.

Fully mocked SOAP objects (SimpleNamespace / Mock) - no network call, no
real vCenter contact.
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.vcenter.authorization_collector import (
    collect,
    collect_privileges,
    collect_roles,
    resolve_role_privileges,
)
from src.vcenter.soap_client import VCenterSoapError


def _role(role_id, name, system=False, label=None, privilege_ids=None):
    return SimpleNamespace(
        roleId=role_id,
        name=name,
        system=system,
        info=SimpleNamespace(label=label or name),
        privilege=privilege_ids or [],
    )


def _privilege(priv_id, name, group_name="System", on_parent=False):
    return SimpleNamespace(privId=priv_id, name=name, privGroupName=group_name, onParent=on_parent)


def _entity(entity_type_name, entity_id):
    # A distinct throwaway class per call, named to match what the real
    # pyVmomi type(entity).__name__ would produce (e.g. "vim.Folder") -
    # avoids mutating any shared class object.
    cls = type(entity_type_name, (), {})
    obj = cls()
    obj._moId = entity_id
    return obj


def _permission(principal, group, role_id, propagate, entity_type_name, entity_id):
    entity = _entity(entity_type_name, entity_id)
    return SimpleNamespace(principal=principal, group=group, roleId=role_id, propagate=propagate, entity=entity)


def _fake_client(roles, privileges, permissions_by_entity):
    """permissions_by_entity: {(object_type, object_id): {"direct": [...], "all": [...]}}"""
    auth_manager = Mock()
    auth_manager.roleList = roles
    auth_manager.privilegeList = privileges

    def _retrieve(entity, inherited):
        key = (type(entity).__name__, entity._moId)
        bucket = permissions_by_entity[key]
        return bucket["all"] if inherited else bucket["direct"]

    auth_manager.RetrieveEntityPermissions.side_effect = _retrieve

    client = Mock()
    client.content.authorizationManager = auth_manager
    client.service_instance._stub = Mock()
    return client


# 1. roleList -> role mapping
def test_collect_roles_builds_role_id_mapping():
    client = _fake_client([_role(-1, "Admin", system=True, privilege_ids=["System.Read"])], [], {})
    roles = collect_roles(client)

    assert roles[-1]["name"] == "Admin"
    assert roles[-1]["system"] is True
    assert roles[-1]["privilege_ids"] == ["System.Read"]


# 2. privilegeList -> privilege mapping
def test_collect_privileges_builds_priv_id_mapping():
    client = _fake_client([], [_privilege("System.Read", "Read", "System")], {})
    privileges = collect_privileges(client)

    assert privileges["System.Read"]["name"] == "Read"
    assert privileges["System.Read"]["group_name"] == "System"


# 3. roleId -> role -> privileges resolution
def test_resolve_role_privileges_follows_role_to_privilege_ids():
    roles_by_id = {-1: {"privilege_ids": ["System.Read", "System.View"]}}
    privileges_by_id = {
        "System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
        "System.View": {"privId": "System.View", "name": "View", "group_name": "System", "on_parent": False},
    }

    resolved = resolve_role_privileges(roles_by_id, privileges_by_id, -1)

    assert [p["name"] for p in resolved] == ["Read", "View"]


def test_resolve_role_privileges_unknown_role_returns_empty():
    assert resolve_role_privileges({}, {}, 999) == []


# 9. unknown roleId handling (privilege id referenced by role but missing from privilegeList)
def test_resolve_role_privileges_preserves_unknown_privilege_id():
    roles_by_id = {-1: {"privilege_ids": ["Some.Unknown.Privilege"]}}
    resolved = resolve_role_privileges(roles_by_id, {}, -1)

    assert resolved == [{"privId": "Some.Unknown.Privilege", "name": None, "group_name": None, "on_parent": None}]


# 4/5/6. permission parsing, group True/False preservation, propagate preservation
def test_collect_preserves_permission_fields():
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [_permission("user1", False, 100, True, "vim.Folder", "group-v2006")],
            "all": [_permission("user1", False, 100, True, "vim.Folder", "group-v2006")],
        }
    }
    client = _fake_client([_role(100, "AppOperator")], [], permissions_by_entity)

    data, status = collect(client, [{"type": "folder", "id": "group-v2006"}])

    assert status.succeeded
    entity_perms = data["entity_permissions"][0]
    direct = entity_perms["direct"][0]
    assert direct["principal"] == "user1"
    assert direct["group"] is False
    assert direct["roleId"] == 100
    assert direct["role_name"] == "AppOperator"
    assert direct["propagate"] is True


def test_collect_preserves_group_true():
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [_permission("some-group", True, 100, True, "vim.Folder", "group-v2006")],
            "all": [_permission("some-group", True, 100, True, "vim.Folder", "group-v2006")],
        }
    }
    client = _fake_client([_role(100, "AppOperator")], [], permissions_by_entity)

    data, _status = collect(client, [{"type": "folder", "id": "group-v2006"}])

    assert data["entity_permissions"][0]["direct"][0]["group"] is True


# 7. direct vs inherited diff
def test_collect_derives_inherited_by_diffing_against_direct():
    direct_perm = _permission("user1", False, 100, True, "vim.Folder", "group-v2006")
    inherited_perm = _permission("ops-carol", False, -2, True, "vim.Folder", "group-d1")
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [direct_perm],
            "all": [direct_perm, inherited_perm],
        }
    }
    client = _fake_client([_role(100, "AppOperator"), _role(-2, "ReadOnly")], [], permissions_by_entity)

    data, _status = collect(client, [{"type": "folder", "id": "group-v2006"}])
    entity_perms = data["entity_permissions"][0]

    assert len(entity_perms["direct"]) == 1
    assert len(entity_perms["inherited"]) == 1
    assert entity_perms["inherited"][0]["principal"] == "ops-carol"
    assert entity_perms["all"] == entity_perms["direct"] + [] or len(entity_perms["all"]) == 2


# 8. entity ManagedObjectReference parsing
def test_collect_records_entity_type_and_id():
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [_permission("user1", False, 100, True, "vim.Folder", "group-v2006")],
            "all": [_permission("user1", False, 100, True, "vim.Folder", "group-v2006")],
        }
    }
    client = _fake_client([_role(100, "AppOperator")], [], permissions_by_entity)

    data, _status = collect(client, [{"type": "folder", "id": "group-v2006"}])
    record = data["entity_permissions"][0]["direct"][0]

    assert record["entity_type"] == "vim.Folder"
    assert record["entity_id"] == "group-v2006"


# unknown roleId on a permission itself (not a role-privilege lookup)
def test_permission_with_unknown_role_id_does_not_crash():
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [_permission("user1", False, 999999, True, "vim.Folder", "group-v2006")],
            "all": [_permission("user1", False, 999999, True, "vim.Folder", "group-v2006")],
        }
    }
    client = _fake_client([], [], permissions_by_entity)

    data, status = collect(client, [{"type": "folder", "id": "group-v2006"}])

    assert status.succeeded
    assert data["entity_permissions"][0]["direct"][0]["role_name"] is None


# 10. duplicate/stable permission identity handling
def test_duplicate_permissions_produce_stable_identity_and_no_false_inherited():
    perm = _permission("user1", False, 100, True, "vim.Folder", "group-v2006")
    perm_dup = _permission("user1", False, 100, True, "vim.Folder", "group-v2006")
    permissions_by_entity = {
        ("vim.Folder", "group-v2006"): {
            "direct": [perm, perm_dup],
            "all": [perm, perm_dup],
        }
    }
    client = _fake_client([_role(100, "AppOperator")], [], permissions_by_entity)

    data, _status = collect(client, [{"type": "folder", "id": "group-v2006"}])
    entity_perms = data["entity_permissions"][0]

    # both duplicates preserved as raw facts, but neither is misclassified as inherited
    assert len(entity_perms["direct"]) == 2
    assert entity_perms["inherited"] == []


# resource-pool entity type support (completeness-audit fix)
def test_collect_supports_resource_pool_entity_type():
    permissions_by_entity = {
        ("vim.ResourcePool", "resgroup-2010"): {
            "direct": [_permission("VSPHERE.LOCAL\\platform-admins", True, -405023589, True, "vim.ResourcePool", "resgroup-2010")],
            "all": [_permission("VSPHERE.LOCAL\\platform-admins", True, -405023589, True, "vim.ResourcePool", "resgroup-2010")],
        }
    }
    client = _fake_client([_role(-405023589, "DangerousRole")], [], permissions_by_entity)

    data, status = collect(client, [{"type": "resource_pool", "id": "resgroup-2010"}])

    assert status.succeeded
    entity_perms = data["entity_permissions"][0]
    assert entity_perms["entity_type"] == "resource_pool"
    direct = entity_perms["direct"][0]
    assert direct["principal"] == "VSPHERE.LOCAL\\platform-admins"
    assert direct["group"] is True
    assert direct["roleId"] == -405023589
    assert direct["role_name"] == "DangerousRole"
    assert direct["propagate"] is True


def test_collect_wraps_soap_failure_as_failed_status_not_raised():
    client = Mock()
    client.content.authorizationManager.roleList = property(lambda self: (_ for _ in ()).throw(Exception("boom")))
    broken_manager = Mock()
    type(broken_manager).roleList = property(lambda self: (_ for _ in ()).throw(Exception("boom")))
    client.content.authorizationManager = broken_manager

    data, status = collect(client, [])

    assert data == {}
    assert not status.succeeded
