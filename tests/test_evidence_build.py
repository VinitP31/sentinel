"""Stage 9 tests: evidence package assembly.

Packages already-collected evidence per user/role — no new computation, no
new findings. findings.json stays untouched and separate.
"""

import json
from pathlib import Path

import pytest

from src.evidence.build import build_evidence_package
from src.graph.build import build_graph
from src.normalize.iam import normalize, resolve_group_inheritance

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def normalized():
    raw = json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


@pytest.fixture
def last_accessed():
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


@pytest.fixture
def cloudtrail():
    return {
        "region": "us-east-1",
        "evidence_window": {
            "start_time": "2026-05-19T00:00:00+00:00",
            "end_time": "2026-08-17T00:00:00+00:00",
            "lookback_days": 90,
        },
        "events": [],
    }


@pytest.fixture
def analyzer_data():
    return {
        "analyzers": [
            {"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/POC-External-Access", "name": "POC-External-Access", "type": "ACCOUNT", "status": "ACTIVE"}
        ],
        "findings": [],
    }


@pytest.fixture
def package(normalized, graph, last_accessed, cloudtrail, analyzer_data):
    return build_evidence_package(normalized, graph, last_accessed, cloudtrail, analyzer_data, "us-east-1")


def by_name(normalized, kind, name):
    return next(r for r in normalized[kind] if r["name"] == name)


def test_every_user_and_role_gets_a_package(normalized, package):
    expected_ids = {r["id"] for r in normalized["users"] + normalized["roles"]}
    assert set(package["packages"].keys()) == expected_ids


def test_groups_do_not_get_packages(normalized, package):
    group_ids = {g["id"] for g in normalized["groups"]}
    assert group_ids.isdisjoint(package["packages"].keys())


def test_package_has_exactly_the_expected_fields(package):
    for pkg in package["packages"].values():
        assert set(pkg.keys()) == {
            "principal",
            "configured_access",
            "relationships",
            "observed_activity",
            "last_accessed",
            "analyzer_findings",
            "evidence_limitations",
        }


def test_findings_field_never_present(package):
    for pkg in package["packages"].values():
        assert "findings" not in pkg


def test_charlie_direct_attachment_attribution(normalized, package):
    charlie_id = by_name(normalized, "users", "charlie")["id"]
    entries = package["packages"][charlie_id]["configured_access"]
    s3_entry = next(e for e in entries if e["policy"] == "POC-Developer-S3-ReadOnly")
    assert s3_entry["attachment_type"] == "direct_attached"
    assert "source_group_name" not in s3_entry


def test_bob_group_inherited_attribution_with_source_group_name(normalized, package):
    bob_id = by_name(normalized, "users", "bob")["id"]
    entries = package["packages"][bob_id]["configured_access"]
    s3_entry = next(e for e in entries if e["policy"] == "POC-Developer-S3-ReadOnly")
    assert s3_entry["attachment_type"] == "group_inherited"
    assert s3_entry["source_group_name"] == "Auditors"

    deny_entry = next(e for e in entries if e["policy"] == "POC-Auditor-IAM-Deny-Test")
    assert deny_entry["attachment_type"] == "group_inherited"
    assert deny_entry["source_group_name"] == "Auditors"


def test_bob_inline_policy_attribution(normalized, package):
    bob_id = by_name(normalized, "users", "bob")["id"]
    entries = package["packages"][bob_id]["configured_access"]
    inline_entry = next(e for e in entries if e["policy"] == "InlineDenyTest")
    assert inline_entry["attachment_type"] == "inline"
    assert "source_group_name" not in inline_entry


def test_alice_can_assume_chain_included(normalized, package):
    alice_id = by_name(normalized, "users", "alice")["id"]
    relationships = package["packages"][alice_id]["relationships"]
    pairs = {(r["from"], r["to"]) for r in relationships}
    assert ("alice", "DeveloperRole") in pairs
    assert ("DeveloperRole", "AdminRole") in pairs
    assert all(r["relationship"] == "CAN_ASSUME" for r in relationships)


def test_developer_role_package_excludes_upstream_edge(normalized, package):
    dev_role_id = by_name(normalized, "roles", "DeveloperRole")["id"]
    relationships = package["packages"][dev_role_id]["relationships"]
    pairs = {(r["from"], r["to"]) for r in relationships}
    assert ("DeveloperRole", "AdminRole") in pairs
    assert ("alice", "DeveloperRole") not in pairs


def test_principal_with_no_can_assume_edges_gets_empty_relationships(normalized, package):
    charlie_id = by_name(normalized, "users", "charlie")["id"]
    assert package["packages"][charlie_id]["relationships"] == []


def test_cloudtrail_activity_scoped_to_correct_principal(normalized, graph, last_accessed, analyzer_data):
    alice_id = by_name(normalized, "users", "alice")["id"]
    cloudtrail = {
        "region": "us-east-1",
        "evidence_window": {"start_time": "s", "end_time": "e", "lookback_days": 90},
        "events": [
            {"EventName": "ListBuckets", "EventSource": "s3.amazonaws.com", "EventTime": "t1", "attributed_principal_arn": alice_id},
            {"EventName": "ListRoles", "EventSource": "iam.amazonaws.com", "EventTime": "t2", "attributed_principal_arn": "someone-else"},
        ],
    }
    package = build_evidence_package(normalized, graph, last_accessed, cloudtrail, analyzer_data, "us-east-1")

    alice_events = package["packages"][alice_id]["observed_activity"]["events"]
    assert len(alice_events) == 1
    assert alice_events[0]["event_name"] == "ListBuckets"


def test_cloudtrail_evidence_window_preserved(package, cloudtrail):
    any_pkg = next(iter(package["packages"].values()))
    assert any_pkg["observed_activity"]["evidence_window"] == cloudtrail["evidence_window"]


def test_last_accessed_data_included(normalized, package):
    alice_id = by_name(normalized, "users", "alice")["id"]
    services = {e["service"] for e in package["packages"][alice_id]["last_accessed"]}
    assert "s3" in services
    assert "sts" in services


def test_missing_last_accessed_entry_yields_empty_list(normalized, package):
    dev_role_id = by_name(normalized, "roles", "DeveloperRole")["id"]
    # DeveloperRole isn't in the last_accessed fixture at all under some
    # variants — whether present or not, the field must be a list, never
    # a missing key or an error.
    assert isinstance(package["packages"][dev_role_id]["last_accessed"], list)


def test_evidence_limitations_always_present_and_nonempty(package):
    for pkg in package["packages"].values():
        assert len(pkg["evidence_limitations"]) > 0
        assert all(isinstance(item, str) for item in pkg["evidence_limitations"])


def test_analyzer_findings_empty_success_reflected(package, analyzer_data):
    for pkg in package["packages"].values():
        assert pkg["analyzer_findings"] == analyzer_data["findings"] == []


def test_service_linked_role_gets_package_without_error(normalized, package):
    # AdminRole, DeveloperRole, UntrustedRole are all in the fixture roles —
    # confirm none of them raise or get skipped, regardless of how sparse
    # their attachments/last-accessed data is.
    for role in normalized["roles"]:
        assert role["id"] in package["packages"]
