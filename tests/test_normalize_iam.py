"""Normalize direct attached + inline policies.

Scope: users, groups, roles, policies, permissions, attachments. No group
inheritance, no CAN_ASSUME graph logic, no usage evidence, no security rules.
"""

import json
from pathlib import Path

import pytest

from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE = Path(__file__).parent / "fixtures" / "raw_iam_authorization_details.json"


@pytest.fixture
def raw():
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def result(raw):
    return normalize(raw)


def by_name(records, name):
    return next(r for r in records if r["name"] == name)


def test_counts_reconcile_against_raw(raw, result):
    assert len(result["users"]) == len(raw["UserDetailList"])
    assert len(result["groups"]) == len(raw["GroupDetailList"])
    assert len(result["roles"]) == len(raw["RoleDetailList"])

    # 3 managed policies from raw["Policies"], plus one inline policy each
    # for bob, DeveloperRole and AdminRole (3 inline policies total).
    assert len(result["policies"]) == len(raw["Policies"]) + 3

    # Direct/inline attachments only, before group inheritance:
    # alice(2 direct) + Developers(direct) + Auditors(2 direct) +
    # charlie(direct) + DeveloperRole(direct) + bob(inline) +
    # DeveloperRole(inline) + AdminRole(inline) = 10.
    assert len(result["attachments"]) == 10


def test_charlie_direct_attachment_recorded(result):
    charlie = by_name(result["users"], "charlie")
    attachment = next(a for a in result["attachments"] if a["principal_id"] == charlie["id"])
    assert attachment["attachment_type"] == "direct_attached"
    policy = next(p for p in result["policies"] if p["id"] == attachment["policy_id"])
    assert policy["name"] == "POC-Developer-S3-ReadOnly"
    assert policy["policy_type"] == "managed"


def test_bob_inline_attachment_recorded(result):
    bob = by_name(result["users"], "bob")
    attachment = next(a for a in result["attachments"] if a["principal_id"] == bob["id"])
    assert attachment["attachment_type"] == "inline"
    policy = next(p for p in result["policies"] if p["id"] == attachment["policy_id"])
    assert policy["policy_type"] == "inline"
    assert policy["name"] == "InlineDenyTest"


def test_deny_statement_survives_normalization(result):
    auditor_policy = by_name(result["policies"], "POC-Auditor-IAM-Deny-Test")
    perms = [p for p in result["permissions"] if p["policy_id"] == auditor_policy["id"]]
    effects = {p["effect"] for p in perms}
    assert "Deny" in effects
    deny = next(p for p in perms if p["effect"] == "Deny")
    assert deny["actions"] == ["iam:GetCredentialReport"]

    allow = next(p for p in perms if p["effect"] == "Allow")
    assert allow["actions"] == ["iam:List*", "iam:Get*"]


def test_bob_inline_deny_survives(result):
    bob = by_name(result["users"], "bob")
    inline_attachment = next(a for a in result["attachments"] if a["principal_id"] == bob["id"])
    perms = [p for p in result["permissions"] if p["policy_id"] == inline_attachment["policy_id"]]
    effects = {p["effect"] for p in perms}
    assert effects == {"Allow", "Deny"}


def test_wildcards_not_expanded(result):
    charlie = by_name(result["users"], "charlie")
    attachment = next(a for a in result["attachments"] if a["principal_id"] == charlie["id"])
    s3_perms = [p for p in result["permissions"] if p["policy_id"] == attachment["policy_id"]]
    assert s3_perms[0]["actions"] == ["s3:GetObject", "s3:ListBucket"]

    bob = by_name(result["users"], "bob")
    bob_attachment = next(a for a in result["attachments"] if a["principal_id"] == bob["id"])
    bob_perms = [p for p in result["permissions"] if p["policy_id"] == bob_attachment["policy_id"]]
    allow = next(p for p in bob_perms if p["effect"] == "Allow")
    assert allow["actions"] == ["s3:*"]
    assert allow["resources"] == ["*"]


def test_url_encoded_document_decoded_without_corruption(result):
    # POC-Developer-S3-ReadOnly ships URL-encoded in the fixture; a decoded
    # dict document with the expected actions proves it was decoded once,
    # correctly, not left encoded or double-decoded.
    policy = by_name(result["policies"], "POC-Developer-S3-ReadOnly")
    assert policy["document"]["Statement"][0]["Action"] == ["s3:GetObject", "s3:ListBucket"]


def test_already_decoded_document_not_corrupted(result):
    # POC-Auditor-IAM-Deny-Test ships as an already-parsed dict in the
    # fixture; passing it through unquote()/json.loads() again would raise.
    policy = by_name(result["policies"], "POC-Auditor-IAM-Deny-Test")
    assert policy["document"]["Statement"][0]["Effect"] == "Allow"


def test_role_trust_policy_captured_verbatim(result):
    role = by_name(result["roles"], "DeveloperRole")
    principals = role["trust_policy"]["Statement"][0]["Principal"]
    assert principals == {"AWS": "arn:aws:iam::123456789012:user/alice"}


def test_no_aws_specific_field_names_leak(result):
    # Layer boundary check: normalized records must not carry raw AWS key
    # names like Arn/PolicyName/CreateDate.
    forbidden = {"Arn", "PolicyName", "CreateDate", "PolicyDocument", "RoleName", "UserName", "GroupName"}
    for bucket in ("users", "groups", "roles", "policies"):
        for record in result[bucket]:
            assert forbidden.isdisjoint(record.keys())


# --- group inheritance -----------------------------------------------------


def attachments_for(inherited_result, principal_id):
    return [a for a in inherited_result["attachments"] if a["principal_id"] == principal_id]


def test_membership_resolution(result):
    alice = by_name(result["users"], "alice")
    bob = by_name(result["users"], "bob")
    charlie = by_name(result["users"], "charlie")

    memberships_by_user = {m["user_id"]: m for m in result["memberships"]}
    assert memberships_by_user[alice["id"]]["group_name"] == "Developers"
    assert memberships_by_user[bob["id"]]["group_name"] == "Auditors"
    assert charlie["id"] not in memberships_by_user


def test_alice_inherits_s3_via_developers(result):
    inherited = resolve_group_inheritance(result)
    alice = by_name(result["users"], "alice")
    s3_policy = by_name(result["policies"], "POC-Developer-S3-ReadOnly")

    alice_group_inherited = [
        a for a in attachments_for(inherited, alice["id"]) if a["attachment_type"] == "group_inherited"
    ]
    assert len(alice_group_inherited) == 1
    attachment = alice_group_inherited[0]
    assert attachment["policy_id"] == s3_policy["id"]
    assert attachment["source_group_name"] == "Developers"


def test_bob_inherits_s3_and_deny_via_auditors(result):
    inherited = resolve_group_inheritance(result)
    bob = by_name(result["users"], "bob")
    s3_policy = by_name(result["policies"], "POC-Developer-S3-ReadOnly")
    deny_policy = by_name(result["policies"], "POC-Auditor-IAM-Deny-Test")

    bob_group_attachments = [
        a for a in attachments_for(inherited, bob["id"]) if a["attachment_type"] == "group_inherited"
    ]
    inherited_policy_ids = {a["policy_id"] for a in bob_group_attachments}
    assert inherited_policy_ids == {s3_policy["id"], deny_policy["id"]}
    assert all(a["source_group_name"] == "Auditors" for a in bob_group_attachments)

    # Bob's own inline attachment (direct, unrelated to Auditors) is untouched.
    inline_attachments = [a for a in attachments_for(inherited, bob["id"]) if a["attachment_type"] == "inline"]
    assert len(inline_attachments) == 1


def test_charlie_s3_access_remains_direct_not_inherited(result):
    inherited = resolve_group_inheritance(result)
    charlie = by_name(result["users"], "charlie")

    charlie_attachments = attachments_for(inherited, charlie["id"])
    assert len(charlie_attachments) == 1
    assert charlie_attachments[0]["attachment_type"] == "direct_attached"
    assert "source_group_name" not in charlie_attachments[0]


def test_auditors_deny_inherited_by_bob_permission_lookup(result):
    # Attribution names the source group; the underlying permission (with
    # Deny intact) is reached via policy_id, not a second permission model.
    inherited = resolve_group_inheritance(result)
    bob = by_name(result["users"], "bob")
    deny_policy = by_name(result["policies"], "POC-Auditor-IAM-Deny-Test")

    bob_inherits_deny_policy = any(
        a["policy_id"] == deny_policy["id"] and a["attachment_type"] == "group_inherited"
        for a in attachments_for(inherited, bob["id"])
    )
    assert bob_inherits_deny_policy

    perms = [p for p in inherited["permissions"] if p["policy_id"] == deny_policy["id"]]
    deny_perm = next(p for p in perms if p["effect"] == "Deny")
    assert deny_perm["actions"] == ["iam:GetCredentialReport"]


def test_direct_and_inline_attachments_unchanged_by_inheritance(result):
    inherited = resolve_group_inheritance(result)
    direct_and_inline_before = [
        a for a in result["attachments"] if a["attachment_type"] in ("direct_attached", "inline")
    ]
    direct_and_inline_after = [
        a for a in inherited["attachments"] if a["attachment_type"] in ("direct_attached", "inline")
    ]
    assert direct_and_inline_after == direct_and_inline_before


def test_no_role_assumption_or_usage_logic_added(result):
    inherited = resolve_group_inheritance(result)
    # Group inheritance must not introduce CAN_ASSUME resolution,
    # activity/usage evidence, or security findings.
    assert set(inherited.keys()) == {
        "users",
        "groups",
        "roles",
        "policies",
        "permissions",
        "attachments",
        "memberships",
    }
    assert not any(a["attachment_type"] == "can_assume" for a in inherited["attachments"])
    for role in inherited["roles"]:
        assert "can_assume" not in role
        assert "last_accessed" not in role
