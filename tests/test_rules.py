"""Deterministic security rules tests.

Scope: broad_permission, administrative_access, potentially_unused_access.
Explicit Deny precedence is exercised as the internal effective-access check
these rules share — there is no standalone Deny finding (see src/analysis/rules.py).
No CAN_ASSUME/graph logic, no AI. potentially_unused_access's CloudTrail
consultation is exercised with an empty events fixture here, so these tests
stay isolated to the last-accessed-only behavior; CloudTrail's suppression
behavior has its own tests in test_potentially_unused_access_cloudtrail.py.
"""

import json
from pathlib import Path

import pytest

from src.analysis import rules
from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def normalized():
    raw = json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def last_accessed():
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


@pytest.fixture
def no_cloudtrail_activity():
    return {"events": []}


@pytest.fixture
def all_findings(normalized, last_accessed, no_cloudtrail_activity):
    return rules.run_all(normalized, last_accessed, no_cloudtrail_activity)


def findings_for(findings, rule, principal_name):
    return [f for f in findings if f["rule"] == rule and f["principal"]["name"] == principal_name]


# --- broad_permission / administrative_access -----------------------------


def test_full_wildcard_fires_both_rules_for_adminrole(all_findings):
    broad = findings_for(all_findings, rules.BROAD_PERMISSION, "AdminRole")
    admin = findings_for(all_findings, rules.ADMINISTRATIVE_ACCESS, "AdminRole")
    assert len(broad) == 1
    assert len(admin) == 1
    assert broad[0]["policy_id"] == admin[0]["policy_id"]
    assert broad[0]["attribution"] == {"attachment_type": "inline"}


def test_service_wildcard_does_not_trigger_broad_or_admin(all_findings):
    # bob's inline policy is Action=s3:*, Resource=* — a service wildcard,
    # not Action=*, Resource=* — must not be treated as full admin access.
    assert findings_for(all_findings, rules.BROAD_PERMISSION, "bob") == []
    assert findings_for(all_findings, rules.ADMINISTRATIVE_ACCESS, "bob") == []


def test_scoped_s3_policy_does_not_trigger_broad_permission(all_findings):
    assert findings_for(all_findings, rules.BROAD_PERMISSION, "charlie") == []
    assert findings_for(all_findings, rules.ADMINISTRATIVE_ACCESS, "charlie") == []


def test_charlie_direct_vs_bob_group_inherited_same_policy_different_attribution(normalized):
    charlie = next(u for u in normalized["users"] if u["name"] == "charlie")
    bob = next(u for u in normalized["users"] if u["name"] == "bob")
    s3_policy = next(p for p in normalized["policies"] if p["name"] == "POC-Developer-S3-ReadOnly")

    charlie_attachment = next(
        a for a in normalized["attachments"] if a["principal_id"] == charlie["id"] and a["policy_id"] == s3_policy["id"]
    )
    bob_attachment = next(
        a for a in normalized["attachments"] if a["principal_id"] == bob["id"] and a["policy_id"] == s3_policy["id"]
    )
    assert charlie_attachment["attachment_type"] == "direct_attached"
    assert bob_attachment["attachment_type"] == "group_inherited"
    assert bob_attachment["source_group_name"] == "Auditors"


# --- Deny precedence (internal to the rules above, no standalone finding) --


def test_narrow_deny_does_not_cancel_broad_allow():
    permissions = [
        {"policy_id": "p", "effect": "Allow", "actions": ["*"], "resources": ["*"]},
        {"policy_id": "p", "effect": "Deny", "actions": ["iam:GetCredentialReport"], "resources": ["*"]},
    ]
    allow = permissions[0]
    assert rules._is_denied(permissions, allow) is False


def test_equally_broad_deny_cancels_full_wildcard_allow():
    permissions = [
        {"policy_id": "p", "effect": "Allow", "actions": ["*"], "resources": ["*"]},
        {"policy_id": "p", "effect": "Deny", "actions": ["*"], "resources": ["*"]},
    ]
    allow = permissions[0]
    assert rules._is_denied(permissions, allow) is True


def test_auditor_allow_survives_its_own_narrow_deny():
    # POC-Auditor-IAM-Deny-Test's Allow iam:List*/iam:Get* must not be
    # canceled by its sibling Deny on the single GetCredentialReport action.
    permissions = [
        {"policy_id": "p", "effect": "Allow", "actions": ["iam:List*", "iam:Get*"], "resources": ["*"]},
        {"policy_id": "p", "effect": "Deny", "actions": ["iam:GetCredentialReport"], "resources": ["*"]},
    ]
    allow = permissions[0]
    assert rules._is_denied(permissions, allow) is False


def test_no_explicit_deny_override_finding_is_ever_emitted(all_findings):
    assert all(f["rule"] != "explicit_deny_override" for f in all_findings)


# --- potentially_unused_access --------------------------------------------


def test_bob_and_charlie_flagged_unused_alice_is_not(all_findings):
    assert findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "alice") == []
    assert len(findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "bob")) >= 1
    assert len(findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "charlie")) >= 1


def test_missing_last_accessed_entry_treated_as_no_activity(all_findings):
    # AdminRole is deliberately absent from the last_accessed fixture,
    # simulating a principal with no last-accessed evidence at all.
    assert len(findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "AdminRole")) == 1


def test_groups_excluded_from_unused_access(all_findings):
    for group_name in ("Developers", "Auditors"):
        assert findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, group_name) == []


def test_unused_access_evidence_window_names_both_sources(all_findings):
    unused = findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "bob")
    assert unused
    for finding in unused:
        assert finding["evidence_window"]["sources_consulted"] == [
            "iam_last_accessed",
            "cloudtrail_event_history",
        ]
        assert "CloudTrail" in finding["evidence_window"]["note"]


def test_wording_never_claims_permanent_non_use(all_findings):
    unused = findings_for(all_findings, rules.POTENTIALLY_UNUSED_ACCESS, "bob")
    for finding in unused:
        assert "never used" not in finding["detail"].lower()
        assert "no corresponding activity observed in the collected evidence" in finding["detail"].lower()


def test_rule_name_is_potentially_unused_access():
    assert rules.POTENTIALLY_UNUSED_ACCESS == "potentially_unused_access"


def test_other_rules_do_not_carry_evidence_window(all_findings):
    for finding in all_findings:
        if finding["rule"] in (rules.BROAD_PERMISSION, rules.ADMINISTRATIVE_ACCESS):
            assert "evidence_window" not in finding


def test_finding_schema_has_only_expected_fields(all_findings):
    allowed = {"rule", "principal", "policy_id", "attribution", "evidence_window", "detail"}
    for finding in all_findings:
        assert set(finding.keys()) <= allowed
        assert set(finding["principal"].keys()) == {"id", "name", "type"}
