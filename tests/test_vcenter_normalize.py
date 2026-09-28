"""vCenter normalization tests.

Fixtures are shaped exactly like inventory_collector.collect() and
authorization_collector.collect()'s real output (field names/structure
match what was actually observed against the real sandbox in Phase 5/6
investigations) - no network call, no real vCenter contact.
"""

import pytest

from src.vcenter.normalize import normalize


def make_inventory(**overrides):
    base = {
        "datacenter": [{"id": "datacenter-2001", "type": "datacenter", "name": "DC-Lab", "parent": None}],
        "folder": [
            {"id": "group-d1", "type": "folder", "name": "Datacenters", "parent": None},
            {"id": "group-v2006", "type": "folder", "name": "AppTeam", "parent": None},
        ],
        "cluster": [],
        "host": [],
        "vm": [],
    }
    base.update(overrides)
    return base


def make_authorization(**overrides):
    base = {
        "roles": {
            1467657722: {"roleId": 1467657722, "name": "AppOperator", "system": False, "label": "AppOperator", "privilege_ids": ["VirtualMachine.Interact.PowerOn"]},
            1148447843: {"roleId": 1148447843, "name": "ReadOnlyPlus", "system": False, "label": "ReadOnlyPlus", "privilege_ids": ["System.Read"]},
            -1: {"roleId": -1, "name": "Admin", "system": True, "label": "Admin", "privilege_ids": ["System.Read", "System.Write", "Folder.Create"]},
        },
        "privileges": {
            "VirtualMachine.Interact.PowerOn": {"privId": "VirtualMachine.Interact.PowerOn", "name": "Power On", "group_name": "VirtualMachine", "on_parent": False},
            "System.Read": {"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False},
            "System.Write": {"privId": "System.Write", "name": "Write", "group_name": "System", "on_parent": False},
            "Folder.Create": {"privId": "Folder.Create", "name": "Create Folder", "group_name": "Folder", "on_parent": False},
        },
        "role_privileges": {
            1467657722: [{"privId": "VirtualMachine.Interact.PowerOn", "name": "Power On", "group_name": "VirtualMachine", "on_parent": False}],
            1148447843: [{"privId": "System.Read", "name": "Read", "group_name": "System", "on_parent": False}],
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
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                    {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
                "inherited": [],
                "all": [
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                    {"principal": "VSPHERE.LOCAL\\Administrators", "group": True, "roleId": -1, "role_name": "Admin", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
            },
            {
                "entity_type": "folder",
                "entity_id": "group-v2006",
                "direct": [
                    {"principal": "OKTA.CALFUS.AI\\ghost-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                    {"principal": "CALFUS.AI\\okta-app-admins", "group": True, "roleId": 1467657722, "role_name": "AppOperator", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                ],
                "inherited": [
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
                "all": [
                    {"principal": "OKTA.CALFUS.AI\\ghost-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                    {"principal": "CALFUS.AI\\okta-app-admins", "group": True, "roleId": 1467657722, "role_name": "AppOperator", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
                    {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "folder", "entity_id": "group-d1"},
                ],
            },
        ],
    }
    base.update(overrides)
    return base


@pytest.fixture
def result():
    return normalize(make_inventory(), make_authorization())


# 1. provider is "vcenter"
def test_all_records_carry_vcenter_provider(result):
    for record in result["users"] + result["groups"] + result["policies"]:
        assert record["provider"] == "vcenter"


# 2. roles become policies (one per (role, entity) binding actually observed -
# see _policy_id in src/vcenter/normalize.py: a shared policy id per bare
# role caused a proven graph cross-contamination bug, fixed by scoping each
# policy to the specific binding it came from)
def test_roles_become_policies(result):
    policy_ids = {p["id"] for p in result["policies"]}
    assert policy_ids == {
        "1148447843@group-d1",
        "-1@group-d1",
        "1148447843@group-v2006",
        "1467657722@group-v2006",
    }
    app_operator = next(p for p in result["policies"] if p["id"] == "1467657722@group-v2006")
    assert app_operator["name"] == "AppOperator"
    assert app_operator["policy_type"] == "custom"
    admin = next(p for p in result["policies"] if p["id"] == "-1@group-d1")
    assert admin["policy_type"] == "system"


# 3. role privilege IDs become permission actions
def test_role_privilege_ids_become_permission_actions(result):
    permissions_by_policy = {p["policy_id"]: p for p in result["permissions"]}
    assert permissions_by_policy["1467657722@group-v2006"]["actions"] == ["VirtualMachine.Interact.PowerOn"]
    assert permissions_by_policy["-1@group-d1"]["actions"] == ["System.Read", "System.Write", "Folder.Create"]


# 4/5. principals become users/groups correctly, group=True does not become a user
def test_principals_split_into_users_and_groups(result):
    user_ids = {u["id"] for u in result["users"]}
    group_ids = {g["id"] for g in result["groups"]}

    assert "OKTA.CALFUS.AI\\ghost-user" in user_ids
    assert "VSPHERE.LOCAL\\ops-carol" in user_ids
    assert "VSPHERE.LOCAL\\Administrators" in group_ids
    assert "CALFUS.AI\\okta-app-admins" in group_ids
    assert "VSPHERE.LOCAL\\Administrators" not in user_ids
    assert "CALFUS.AI\\okta-app-admins" not in user_ids


# 6. permissions become attachments
def test_permissions_become_attachments(result):
    # 2 direct on root (ops-carol, Administrators) + 2 direct on AppTeam
    # (ghost-user, okta-app-admins). ops-carol's "inherited" sighting on
    # AppTeam names entity_id=group-d1 - the SAME entity as her direct
    # grant on root - so it collapses into that one record rather than
    # counting as a 5th attachment (see _attachment_identity in normalize.py).
    assert len(result["attachments"]) == 4


# 7/8/9. entity_id, entity_type, propagate preserved
def test_attachment_preserves_entity_and_propagate(result):
    ghost_user_attachment = next(a for a in result["attachments"] if a["principal_id"] == "OKTA.CALFUS.AI\\ghost-user")
    assert ghost_user_attachment["entity_id"] == "group-v2006"
    assert ghost_user_attachment["entity_type"] == "folder"
    assert ghost_user_attachment["propagate"] is True
    assert ghost_user_attachment["entity_name"] == "AppTeam"


# 10. direct/inherited attachment distinction preserved for genuinely
# different entities - but a direct sighting and an inherited sighting of
# the SAME entity (see normalize.py's _attachment_identity) collapse to one
# record, since they describe the same real-world fact, not two.
def test_direct_and_inherited_preserved_for_genuinely_different_entities():
    inventory = make_inventory()
    authorization = make_authorization()
    # A principal whose grant is defined at an entity outside this run's
    # queried set (e.g. a Datastore, which inventory_collector does not
    # collect) - it can only ever be observed via an "inherited" sighting
    # naming that entity, never a matching "direct" one. This is the
    # genuine "inherited, no direct counterpart" case.
    authorization["entity_permissions"].append(
        {
            "entity_type": "folder",
            "entity_id": "group-v2006",
            "direct": [],
            "inherited": [
                {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
            "all": [
                {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
        }
    )
    normalized = normalize(inventory, authorization)
    ops_carol_attachments = [a for a in normalized["attachments"] if a["principal_id"] == "VSPHERE.LOCAL\\ops-carol"]
    types_by_entity = {a["entity_id"]: a["attachment_type"] for a in ops_carol_attachments}
    assert types_by_entity["group-d1"] == "vcenter_direct"  # her real direct grant on root
    assert types_by_entity["datastore-uncollected"] == "vcenter_inherited"  # genuinely different entity, stays inherited
    assert len(ops_carol_attachments) == 2


# 11. duplicate principals are deduplicated
def test_duplicate_principal_produces_one_identity_record(result):
    ops_carol_records = [u for u in result["users"] if u["id"] == "VSPHERE.LOCAL\\ops-carol"]
    assert len(ops_carol_records) == 1


# 12. multiple permissions for the same principal, at genuinely different
# entities, are preserved as separate attachments
def test_multiple_attachments_for_same_principal_preserved():
    inventory = make_inventory()
    authorization = make_authorization()
    # Give ops-carol a second, genuinely distinct direct grant on AppTeam
    # (a different policy/role than her root grant).
    authorization["entity_permissions"][1]["direct"].append(
        {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1467657722, "role_name": "AppOperator", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
    )
    authorization["entity_permissions"][1]["all"].append(
        {"principal": "VSPHERE.LOCAL\\ops-carol", "group": False, "roleId": 1467657722, "role_name": "AppOperator", "propagate": True, "entity_type": "folder", "entity_id": "group-v2006"},
    )
    normalized = normalize(inventory, authorization)
    ops_carol_attachments = [a for a in normalized["attachments"] if a["principal_id"] == "VSPHERE.LOCAL\\ops-carol"]
    assert len(ops_carol_attachments) == 2
    assert {a["entity_id"] for a in ops_carol_attachments} == {"group-d1", "group-v2006"}


# 13. no fake memberships are generated
def test_no_memberships_generated(result):
    assert result["memberships"] == []


def test_inherited_grant_rediscovered_at_multiple_entities_is_deduplicated():
    """A grant defined at an entity outside this run's queried set (e.g. a
    Datastore, which inventory_collector does not collect) is rediscovered,
    identically, once per queried descendant entity that inherits it (its
    own entity_id always points to where it is actually defined, never the
    entity being queried). Confirmed as a real bug against the real vCenter
    sandbox: one real grant produced up to 20 duplicate "affected entity"
    records before this dedup was added. Two queried entities rediscovering
    the SAME (principal, policy, entity) fact must collapse to exactly one
    attachment - here using a principal with no matching "direct" sighting
    anywhere, so the result is unambiguously the pure inherited+inherited
    dedup case, not direct-overriding-inherited (see the separate
    test_direct_and_inherited_preserved_for_genuinely_different_entities)."""
    inventory = make_inventory()
    authorization = make_authorization()
    authorization["entity_permissions"].append(
        {
            "entity_type": "folder",
            "entity_id": "group-v2006",
            "direct": [],
            "inherited": [
                {"principal": "VSPHERE.LOCAL\\datastore-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
            "all": [
                {"principal": "VSPHERE.LOCAL\\datastore-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
        }
    )
    authorization["entity_permissions"].append(
        {
            "entity_type": "cluster",
            "entity_id": "domain-c1",
            "direct": [],
            "inherited": [
                {"principal": "VSPHERE.LOCAL\\datastore-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
            "all": [
                {"principal": "VSPHERE.LOCAL\\datastore-user", "group": False, "roleId": 1148447843, "role_name": "ReadOnlyPlus", "propagate": True, "entity_type": "datastore", "entity_id": "datastore-uncollected"},
            ],
        }
    )

    normalized = normalize(inventory, authorization)
    attachments = [a for a in normalized["attachments"] if a["principal_id"] == "VSPHERE.LOCAL\\datastore-user"]
    assert len(attachments) == 1
    assert attachments[0]["attachment_type"] == "vcenter_inherited"
    assert attachments[0]["entity_id"] == "datastore-uncollected"


# 14. Administrator privileges are NOT converted to "*"
def test_admin_role_privileges_not_converted_to_wildcard(result):
    admin_permission = next(p for p in result["permissions"] if p["policy_id"] == "-1@group-d1")
    assert "*" not in admin_permission["actions"]
    assert admin_permission["actions"] == ["System.Read", "System.Write", "Folder.Create"]


# 15. No Access is NOT invented
def test_no_access_not_invented_when_absent(result):
    assert all(p["effect"] == "Allow" for p in result["permissions"])
    assert not any(policy["name"] == "No Access" for policy in result["policies"])


def test_roles_key_present_but_empty():
    """vCenter has no assumable-role principal concept - present, but empty,
    so graph/build.py's fixed iteration over ("users","groups","roles")
    doesn't KeyError once this feeds the shared pipeline."""
    data = normalize(make_inventory(), make_authorization())
    assert data["roles"] == []


def test_unused_role_still_becomes_a_policy_with_empty_resources():
    """A role that exists in roleList but was never observed bound to any
    collected entity is still preserved as a policy - nothing is dropped -
    with an empty resources list, not an invented one."""
    authorization = make_authorization()
    authorization["roles"][2000] = {"roleId": 2000, "name": "UnusedRole", "system": False, "label": "UnusedRole", "privilege_ids": []}
    authorization["role_privileges"][2000] = []

    data = normalize(make_inventory(), authorization)

    unused_permission = next(p for p in data["permissions"] if p["policy_id"] == "2000")
    assert unused_permission["resources"] == []


# resource-pool entity type support (completeness-audit fix) - shaped after
# the real sandbox case: VSPHERE.LOCAL\platform-admins -> DangerousRole,
# direct at resource pool resgroup-2010.
def test_resource_pool_permission_survives_normalization():
    inventory = make_inventory(resource_pool=[{"id": "resgroup-2010", "type": "resource_pool", "name": "Resources", "parent": None}])
    authorization = make_authorization()
    authorization["roles"][-405023589] = {"roleId": -405023589, "name": "DangerousRole", "system": False, "label": "DangerousRole", "privilege_ids": ["Global.Settings"]}
    authorization["role_privileges"][-405023589] = [{"privId": "Global.Settings", "name": "Settings", "group_name": "Global", "on_parent": False}]
    authorization["entity_permissions"].append(
        {
            "entity_type": "resource_pool",
            "entity_id": "resgroup-2010",
            "direct": [
                {"principal": "VSPHERE.LOCAL\\platform-admins", "group": True, "roleId": -405023589, "role_name": "DangerousRole", "propagate": True, "entity_type": "resource_pool", "entity_id": "resgroup-2010"},
            ],
            "inherited": [],
            "all": [
                {"principal": "VSPHERE.LOCAL\\platform-admins", "group": True, "roleId": -405023589, "role_name": "DangerousRole", "propagate": True, "entity_type": "resource_pool", "entity_id": "resgroup-2010"},
            ],
        }
    )

    data = normalize(inventory, authorization)

    attachment = next(a for a in data["attachments"] if a["entity_id"] == "resgroup-2010")
    assert attachment["principal_id"] == "VSPHERE.LOCAL\\platform-admins"
    assert attachment["entity_type"] == "resource_pool"
    assert attachment["entity_name"] == "Resources"
    assert attachment["attachment_type"] == "vcenter_direct"
    assert attachment["propagate"] is True

    policy = next(p for p in data["policies"] if p["id"] == "-405023589@resgroup-2010")
    assert policy["name"] == "DangerousRole"
    permission = next(p for p in data["permissions"] if p["policy_id"] == "-405023589@resgroup-2010")
    assert permission["resources"] == ["resgroup-2010"]
    assert "Global.Settings" in permission["actions"]

    group_record = next(g for g in data["groups"] if g["id"] == "VSPHERE.LOCAL\\platform-admins")
    assert group_record["type"] == "group"
