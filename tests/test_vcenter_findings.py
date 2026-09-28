"""vCenter deterministic findings tests. Small fixtures only, no network."""

from src.vcenter.findings import (
    HIGH_IMPACT_PRIVILEGES,
    VCENTER_ADMIN_001,
    VCENTER_AUTH_001,
    VCENTER_NOACCESS_001,
    VCENTER_PRIV_001,
    curate_privileges,
    find_administrative_access,
    find_authorization_management_access,
    find_high_impact_privilege_access,
    find_no_access_override,
    run_all,
)


def make_normalized(**overrides):
    base = {
        "users": [
            {"provider": "vcenter", "type": "user", "id": "VSPHERE.LOCAL\\ops-carol", "name": "VSPHERE.LOCAL\\ops-carol", "arn": None, "created_at": None},
            {"provider": "vcenter", "type": "user", "id": "VSPHERE.LOCAL\\svc-conn-min", "name": "VSPHERE.LOCAL\\svc-conn-min", "arn": None, "created_at": None},
        ],
        "groups": [
            {"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\Administrators", "name": "VSPHERE.LOCAL\\Administrators", "arn": None, "created_at": None},
        ],
        "roles": [],
        "policies": [
            {"provider": "vcenter", "type": "policy", "id": "-1@group-d1", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "579378617@group-d1", "name": "ConnectorReaderPlus", "arn": None, "policy_type": "custom", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "1148447843@group-v2006", "name": "ReadOnlyPlus", "arn": None, "policy_type": "custom", "document": None},
        ],
        "permissions": [
            {"policy_id": "-1@group-d1", "effect": "Allow", "actions": ["System.Read", "System.Write", "Folder.Create"], "resources": ["group-d1"]},
            {"policy_id": "579378617@group-d1", "effect": "Allow", "actions": ["System.View", "Authorization.ModifyPermissions"], "resources": ["group-d1"]},
            {"policy_id": "1148447843@group-v2006", "effect": "Allow", "actions": ["System.View"], "resources": ["group-v2006"]},
        ],
        "attachments": [
            {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\svc-conn-min", "policy_id": "579378617@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1148447843@group-v2006", "attachment_type": "vcenter_direct", "entity_id": "group-v2006", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True},
        ],
        "memberships": [],
    }
    base.update(overrides)
    return base


def _entity_ids(entry):
    return {a["entity_id"] for a in entry["assignments"]}


def _principal_by_id(finding, principal_id):
    return next(p for p in finding["principals"] if p["principal"]["id"] == principal_id)


# 1. Administrator direct assignment creates finding
def test_admin_direct_assignment_creates_finding():
    findings = find_administrative_access(make_normalized())
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == VCENTER_ADMIN_001
    assert len(finding["principals"]) == 1
    entry = finding["principals"][0]
    assert entry["assignments"][0]["attachment_type"] == "vcenter_direct"
    assert entry["principal"]["id"] == "VSPHERE.LOCAL\\Administrators"


# 2. Administrator inherited assignment creates finding
def test_admin_inherited_assignment_creates_finding():
    normalized = make_normalized()
    normalized["attachments"][0]["attachment_type"] = "vcenter_inherited"
    findings = find_administrative_access(normalized)
    assert len(findings) == 1
    assert findings[0]["principals"][0]["assignments"][0]["attachment_type"] == "vcenter_inherited"


# 3. Normal role does not create Administrator finding
def test_normal_role_does_not_create_admin_finding():
    normalized = make_normalized(attachments=[
        {"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1148447843@group-v2006", "attachment_type": "vcenter_direct", "entity_id": "group-v2006", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True},
    ])
    assert find_administrative_access(normalized) == []


# 4. Custom role named like "DangerousRole" does NOT trigger Administrator finding
def test_custom_role_named_dangerous_does_not_trigger_admin_finding():
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "-405023589@group-d1", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "-405023589@group-d1", "effect": "Allow", "actions": ["System.Read", "System.Write", "Folder.Create", "VirtualMachine.Config.Rename"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "-405023589@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    assert find_administrative_access(normalized) == []


def test_system_role_named_something_else_does_not_trigger_admin_finding():
    """system == True alone is not enough - the name must also match."""
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "1003@group-d1", "name": "vSphere Client Solution User", "arn": None, "policy_type": "system", "document": None}],
        permissions=[{"policy_id": "1003@group-d1", "effect": "Allow", "actions": ["System.Read"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1003@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    assert find_administrative_access(normalized) == []


# 5. Role containing ModifyPermissions creates authorization-management finding
def test_modify_permissions_privilege_creates_auth_management_finding():
    findings = find_authorization_management_access(make_normalized())
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == VCENTER_AUTH_001
    assert len(finding["principals"]) == 1
    entry = finding["principals"][0]
    assert entry["principal"]["id"] == "VSPHERE.LOCAL\\svc-conn-min"
    assert entry["privileges"] == ["Authorization.ModifyPermissions"]


def test_modify_permissions_detail_does_not_claim_role_modification():
    """Authorization.ModifyPermissions alone must never be described as
    touching roles - only Authorization.ModifyRoles justifies that
    wording."""
    findings = find_authorization_management_access(make_normalized())
    detail = findings[0]["detail"]
    assert "permissions." in detail
    assert "roles" not in detail


def test_modify_roles_detail_does_claim_role_modification():
    normalized = make_normalized(
        permissions=[{"policy_id": "579378617@group-d1", "effect": "Allow", "actions": ["System.View", "Authorization.ModifyRoles"], "resources": ["group-d1"]}],
    )
    findings = find_authorization_management_access(normalized)
    assert "permissions or roles" in findings[0]["detail"]


# 6. Role without sensitive authorization privileges does not create that finding
def test_role_without_sensitive_privileges_no_auth_management_finding():
    normalized = make_normalized(attachments=[
        {"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1148447843@group-v2006", "attachment_type": "vcenter_direct", "entity_id": "group-v2006", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True},
    ])
    assert find_authorization_management_access(normalized) == []


def test_administrator_excluded_from_auth_management_finding_to_avoid_double_count():
    findings = find_authorization_management_access(make_normalized())
    principal_ids = {p["principal"]["id"] for f in findings for p in f["principals"]}
    assert "VSPHERE.LOCAL\\Administrators" not in principal_ids


# 7. Group permission remains a group finding
def test_group_permission_reported_as_group_not_expanded_to_members():
    finding = find_administrative_access(make_normalized())[0]
    entry = finding["principals"][0]
    assert entry["principal"]["type"] == "group"
    assert "member" not in finding["detail"].lower()


# 8. Entity/scope is preserved
def test_entity_scope_preserved():
    finding = find_administrative_access(make_normalized())[0]
    entry = finding["principals"][0]
    assert _entity_ids(entry) == {"group-d1"}
    assert entry["assignments"][0]["entity_name"] == "Datacenters"


# 9. Propagation is preserved
def test_propagation_preserved():
    normalized = make_normalized()
    normalized["attachments"][0]["propagate"] = False
    finding = find_administrative_access(normalized)[0]
    assert finding["principals"][0]["assignments"][0]["propagate"] is False


# 10. Multiple principals produce separate principal entries within one finding
def test_multiple_principals_produce_separate_entries_in_one_finding():
    normalized = make_normalized(attachments=[
        {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
        {"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
    ])
    findings = find_administrative_access(normalized)
    assert len(findings) == 1
    assert len(findings[0]["principals"]) == 2
    principal_ids = {p["principal"]["id"] for p in findings[0]["principals"]}
    assert principal_ids == {"VSPHERE.LOCAL\\Administrators", "VSPHERE.LOCAL\\ops-carol"}


# 11. Same role assigned at different entities does not leak resources between principal entries
def test_same_role_different_entities_no_resource_leak():
    normalized = make_normalized(
        policies=[
            {"provider": "vcenter", "type": "policy", "id": "-1@group-d1", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "-1@group-v2006", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
        ],
        permissions=[
            {"policy_id": "-1@group-d1", "effect": "Allow", "actions": ["System.Read"], "resources": ["group-d1"]},
            {"policy_id": "-1@group-v2006", "effect": "Allow", "actions": ["System.Read"], "resources": ["group-v2006"]},
        ],
        attachments=[
            {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "-1@group-v2006", "attachment_type": "vcenter_direct", "entity_id": "group-v2006", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True},
        ],
    )
    finding = find_administrative_access(normalized)[0]
    admins_entry = _principal_by_id(finding, "VSPHERE.LOCAL\\Administrators")
    carol_entry = _principal_by_id(finding, "VSPHERE.LOCAL\\ops-carol")
    assert _entity_ids(admins_entry) == {"group-d1"}
    assert _entity_ids(carol_entry) == {"group-v2006"}


def test_same_principal_same_role_multiple_entities_grouped_into_one_entry():
    """The real-world case: one grant with propagate=True, visible via
    inheritance at every descendant entity - must become ONE principal
    entry with every entity preserved, not one entry per entity."""
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "-1@group-d1", "name": "Admin", "arn": None, "policy_type": "system", "document": None}],
        permissions=[{"policy_id": "-1@group-d1", "effect": "Allow", "actions": ["System.Read"], "resources": ["group-d1"]}],
        attachments=[
            {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_inherited", "entity_id": "group-v2006", "entity_type": "folder", "entity_name": "AppTeam", "propagate": True},
        ],
    )
    finding = find_administrative_access(normalized)[0]
    assert len(finding["principals"]) == 1
    entry = finding["principals"][0]
    assert _entity_ids(entry) == {"group-d1", "group-v2006"}
    assert len(entry["assignments"]) == 2


# 12. No wildcard "*" is introduced
def test_no_wildcard_introduced_anywhere():
    findings = run_all(make_normalized())
    for finding in findings:
        for entry in finding["principals"]:
            assert "*" not in entry["privileges"]
        assert "*" not in finding.get("notable_privileges", [])


def test_run_all_combines_both_rules():
    findings = run_all(make_normalized())
    ids = {f["id"] for f in findings}
    assert ids == {VCENTER_ADMIN_001, VCENTER_AUTH_001}


def test_severity_is_deterministic_metadata():
    findings = run_all(make_normalized())
    admin_finding = next(f for f in findings if f["id"] == VCENTER_ADMIN_001)
    auth_finding = next(f for f in findings if f["id"] == VCENTER_AUTH_001)
    assert admin_finding["severity"] == "high"
    assert auth_finding["severity"] == "medium"


def test_no_matches_returns_empty_list_not_manufactured():
    assert find_administrative_access(make_normalized(attachments=[])) == []
    assert find_authorization_management_access(make_normalized(attachments=[])) == []


# curate_privileges
def test_curate_privileges_returns_everything_under_cap():
    shown, total = curate_privileges(["System.Read", "System.Write"], cap=10)
    assert total == 2
    assert shown == ["System.Read", "System.Write"]


def test_curate_privileges_prioritizes_notable_and_reports_true_total():
    privileges = [f"System.Priv{i}" for i in range(20)] + ["Authorization.ModifyPermissions"]
    shown, total = curate_privileges(privileges, cap=5)
    assert total == 21
    assert "Authorization.ModifyPermissions" in shown
    assert len(shown) == 5


def test_curate_privileges_never_invents_a_privilege():
    privileges = ["System.Read", "System.Write", "Folder.Create"]
    shown, total = curate_privileges(privileges, cap=2)
    assert all(p in privileges for p in shown)
    assert total == 3


# --- VCENTER-NOACCESS-001: No Access override -------------------------------


def _no_access_normalized(**overrides):
    base = {
        "groups": [{"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\ReadOnlyUsers", "name": "VSPHERE.LOCAL\\ReadOnlyUsers", "arn": None, "created_at": None}],
        "policies": [{"provider": "vcenter", "type": "policy", "id": "-5@group-v1010", "name": "NoAccess", "arn": None, "policy_type": "system", "document": None}],
        "permissions": [{"policy_id": "-5@group-v1010", "effect": "Allow", "actions": [], "resources": ["group-v1010"]}],
        "attachments": [
            {"principal_id": "VSPHERE.LOCAL\\ReadOnlyUsers", "policy_id": "-5@group-v1010", "attachment_type": "vcenter_direct", "entity_id": "group-v1010", "entity_type": "folder", "entity_name": "Sensitive", "propagate": True},
        ],
    }
    return make_normalized(**{**base, **overrides})


def test_no_access_role_creates_no_access_override_finding():
    findings = find_no_access_override(_no_access_normalized())
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == VCENTER_NOACCESS_001
    assert finding["title"] == "No Access Override"
    entry = finding["principals"][0]
    assert entry["principal"]["id"] == "VSPHERE.LOCAL\\ReadOnlyUsers"
    assert entry["principal"]["type"] == "group"
    assert entry["assignments"][0]["entity_name"] == "Sensitive"
    assert entry["assignments"][0]["attachment_type"] == "vcenter_direct"


def test_no_access_finding_severity_is_review_not_high():
    """Treated as a restriction to verify, not a vulnerability - REVIEW
    (medium), never HIGH RISK."""
    finding = find_no_access_override(_no_access_normalized())[0]
    assert finding["severity"] == "medium"


def test_no_access_role_grants_zero_privileges():
    finding = find_no_access_override(_no_access_normalized())[0]
    assert finding["principals"][0]["privileges"] == []


def test_no_access_detail_does_not_assert_a_vulnerability():
    finding = find_no_access_override(_no_access_normalized())[0]
    assert "not asserted as a vulnerability" in finding["detail"]


def test_custom_role_with_zero_privileges_is_not_mistaken_for_no_access():
    """A role id must be exactly the reserved -5 - a custom role that
    happens to also carry zero privileges is not No Access."""
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "999@group-d1", "name": "EmptyCustomRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "999@group-d1", "effect": "Allow", "actions": [], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "999@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    assert find_no_access_override(normalized) == []


def test_no_access_no_matches_returns_empty_list():
    assert find_no_access_override(make_normalized()) == []


# --- VCENTER-PRIV-001: High-Impact Privilege Access -------------------------


def test_high_impact_privileges_create_finding():
    normalized = make_normalized(
        groups=[{"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\platform-admins", "name": "VSPHERE.LOCAL\\platform-admins", "arn": None, "created_at": None}],
        policies=[{"provider": "vcenter", "type": "policy", "id": "-405023589@group-d1", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "-405023589@group-d1", "effect": "Allow", "actions": ["Global.Settings", "Host.Config.Settings", "Sessions.TerminateSession", "System.Read", "System.View"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\platform-admins", "policy_id": "-405023589@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    findings = find_high_impact_privilege_access(normalized)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == VCENTER_PRIV_001
    assert finding["severity"] == "high"
    entry = finding["principals"][0]
    assert entry["principal"]["id"] == "VSPHERE.LOCAL\\platform-admins"
    assert entry["principal"]["type"] == "group"
    assert sorted(entry["privileges"]) == sorted(HIGH_IMPACT_PRIVILEGES)
    assert sorted(finding["high_impact_privileges"]) == sorted(HIGH_IMPACT_PRIVILEGES)


def test_high_impact_privilege_evidence_is_narrowed_to_matched_privileges_only():
    """entry["privileges"] must be exactly the high-impact subset actually
    matched, never the role's full action list."""
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "-405023589@group-d1", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "-405023589@group-d1", "effect": "Allow", "actions": ["Global.Settings", "System.Read", "System.View"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "-405023589@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    entry = find_high_impact_privilege_access(normalized)[0]["principals"][0]
    assert entry["privileges"] == ["Global.Settings"]
    assert "System.Read" not in entry["privileges"]
    assert "System.View" not in entry["privileges"]


def test_single_high_impact_privilege_still_triggers_finding():
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "1034@group-d1", "name": "VsmSvcRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "1034@group-d1", "effect": "Allow", "actions": ["Sessions.TerminateSession"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1034@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    findings = find_high_impact_privilege_access(normalized)
    assert len(findings) == 1
    assert findings[0]["principals"][0]["privileges"] == ["Sessions.TerminateSession"]


def test_role_without_high_impact_privileges_no_finding():
    assert find_high_impact_privilege_access(make_normalized()) == []


def test_admin_role_excluded_from_high_impact_finding_to_avoid_double_count():
    normalized = make_normalized(
        permissions=[{"policy_id": "-1@group-d1", "effect": "Allow", "actions": ["Global.Settings", "Sessions.TerminateSession", "System.Read"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    assert find_high_impact_privilege_access(normalized) == []


def test_role_with_high_impact_privilege_but_no_binding_never_flagged():
    """A role defined with a high-impact privilege but never actually bound
    to any principal produces no attachment record and must never appear -
    only real, observed bindings are ever reported."""
    normalized = make_normalized(attachments=[])
    assert find_high_impact_privilege_access(normalized) == []


# resource-pool entity type support (completeness-audit fix) - the real
# sandbox case: VSPHERE.LOCAL\platform-admins holds DangerousRole at both
# group-d1 (folder, already collected) and resgroup-2010 (resource pool,
# newly collected) - grouping by (principal, role_id) means the existing
# finding's scope naturally widens with no change to finding logic itself.
def test_resource_pool_binding_widens_existing_high_impact_finding_scope():
    normalized = make_normalized(
        groups=[{"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\platform-admins", "name": "VSPHERE.LOCAL\\platform-admins", "arn": None, "created_at": None}],
        policies=[
            {"provider": "vcenter", "type": "policy", "id": "-405023589@group-d1", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "-405023589@resgroup-2010", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None},
        ],
        permissions=[
            {"policy_id": "-405023589@group-d1", "effect": "Allow", "actions": ["Global.Settings", "Sessions.TerminateSession"], "resources": ["group-d1"]},
            {"policy_id": "-405023589@resgroup-2010", "effect": "Allow", "actions": ["Global.Settings", "Sessions.TerminateSession"], "resources": ["resgroup-2010"]},
        ],
        attachments=[
            {"principal_id": "VSPHERE.LOCAL\\platform-admins", "policy_id": "-405023589@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\platform-admins", "policy_id": "-405023589@resgroup-2010", "attachment_type": "vcenter_direct", "entity_id": "resgroup-2010", "entity_type": "resource_pool", "entity_name": "Resources", "propagate": True},
        ],
    )
    findings = find_high_impact_privilege_access(normalized)
    assert len(findings) == 1
    entry = _principal_by_id(findings[0], "VSPHERE.LOCAL\\platform-admins")
    assert _entity_ids(entry) == {"group-d1", "resgroup-2010"}
    entity_types = {a["entity_type"] for a in entry["assignments"]}
    assert entity_types == {"folder", "resource_pool"}


def test_high_impact_privilege_wording_names_only_what_was_found():
    normalized = make_normalized(
        policies=[{"provider": "vcenter", "type": "policy", "id": "1034@group-d1", "name": "VsmSvcRole", "arn": None, "policy_type": "custom", "document": None}],
        permissions=[{"policy_id": "1034@group-d1", "effect": "Allow", "actions": ["Sessions.TerminateSession"], "resources": ["group-d1"]}],
        attachments=[{"principal_id": "VSPHERE.LOCAL\\ops-carol", "policy_id": "1034@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True}],
    )
    detail = find_high_impact_privilege_access(normalized)[0]["detail"]
    assert "Sessions.TerminateSession" in detail
    assert "Global.Settings" not in detail
    assert "Host.Config.Settings" not in detail


# --- run_all: both new rules combine correctly with the existing two -------


def test_run_all_includes_no_access_and_high_impact_when_present():
    normalized = make_normalized(
        groups=[
            {"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\Administrators", "name": "VSPHERE.LOCAL\\Administrators", "arn": None, "created_at": None},
            {"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\ReadOnlyUsers", "name": "VSPHERE.LOCAL\\ReadOnlyUsers", "arn": None, "created_at": None},
            {"provider": "vcenter", "type": "group", "id": "VSPHERE.LOCAL\\platform-admins", "name": "VSPHERE.LOCAL\\platform-admins", "arn": None, "created_at": None},
        ],
        policies=[
            {"provider": "vcenter", "type": "policy", "id": "-1@group-d1", "name": "Admin", "arn": None, "policy_type": "system", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "579378617@group-d1", "name": "ConnectorReaderPlus", "arn": None, "policy_type": "custom", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "-5@group-v1010", "name": "NoAccess", "arn": None, "policy_type": "system", "document": None},
            {"provider": "vcenter", "type": "policy", "id": "-405023589@group-d1", "name": "DangerousRole", "arn": None, "policy_type": "custom", "document": None},
        ],
        permissions=[
            {"policy_id": "-1@group-d1", "effect": "Allow", "actions": ["System.Read"], "resources": ["group-d1"]},
            {"policy_id": "579378617@group-d1", "effect": "Allow", "actions": ["System.View", "Authorization.ModifyPermissions"], "resources": ["group-d1"]},
            {"policy_id": "-5@group-v1010", "effect": "Allow", "actions": [], "resources": ["group-v1010"]},
            {"policy_id": "-405023589@group-d1", "effect": "Allow", "actions": ["Global.Settings"], "resources": ["group-d1"]},
        ],
        attachments=[
            {"principal_id": "VSPHERE.LOCAL\\Administrators", "policy_id": "-1@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\svc-conn-min", "policy_id": "579378617@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\ReadOnlyUsers", "policy_id": "-5@group-v1010", "attachment_type": "vcenter_direct", "entity_id": "group-v1010", "entity_type": "folder", "entity_name": "Sensitive", "propagate": True},
            {"principal_id": "VSPHERE.LOCAL\\platform-admins", "policy_id": "-405023589@group-d1", "attachment_type": "vcenter_direct", "entity_id": "group-d1", "entity_type": "folder", "entity_name": "Datacenters", "propagate": True},
        ],
    )
    findings = run_all(normalized)
    ids = {f["id"] for f in findings}
    assert ids == {VCENTER_ADMIN_001, VCENTER_AUTH_001, VCENTER_NOACCESS_001, VCENTER_PRIV_001}
