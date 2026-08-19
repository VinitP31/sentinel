"""potentially_unused_access consulting both usage sources.

The two evidence sources must never be reconciled by
preferring whichever is non-empty — activity in either counts, and neither
source overrides what the other reports. These tests exercise that logic
directly against the fixture's charlie (S3, direct_attached, no last-accessed
activity by fixture default).
"""

import json
from pathlib import Path

import pytest

from src.analysis import rules

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def normalized():
    from src.normalize.iam import normalize, resolve_group_inheritance

    raw = json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def last_accessed():
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


def cloudtrail_with_event(principal_arn, event_source):
    return {
        "events": [
            {
                "EventId": "evt-1",
                "EventName": "ListBuckets",
                "EventSource": event_source,
                "attributed_principal_arn": principal_arn,
            }
        ]
    }


def findings_for(findings, rule, principal_name):
    return [f for f in findings if f["rule"] == rule and f["principal"]["name"] == principal_name]


def test_no_activity_in_either_source_still_flags_unused(normalized, last_accessed):
    findings = rules.potentially_unused_access(normalized, last_accessed, {"events": []})
    assert findings_for(findings, rules.POTENTIALLY_UNUSED_ACCESS, "charlie")


def test_cloudtrail_only_activity_prevents_finding(normalized, last_accessed):
    charlie_id = next(u for u in normalized["users"] if u["name"] == "charlie")["id"]
    cloudtrail = cloudtrail_with_event(charlie_id, "s3.amazonaws.com")

    findings = rules.potentially_unused_access(normalized, last_accessed, cloudtrail)

    assert findings_for(findings, rules.POTENTIALLY_UNUSED_ACCESS, "charlie") == []


def test_last_accessed_and_cloudtrail_both_showing_activity(normalized):
    # alice already has s3/sts last-accessed activity in the fixture; adding
    # CloudTrail activity too must not produce a duplicate or conflicting
    # outcome — she still isn't flagged.
    alice_id = next(u for u in normalized["users"] if u["name"] == "alice")["id"]
    last_accessed_with_alice_active = json.loads((FIXTURE_DIR / "last_accessed.json").read_text())
    cloudtrail = cloudtrail_with_event(alice_id, "s3.amazonaws.com")

    findings = rules.potentially_unused_access(normalized, last_accessed_with_alice_active, cloudtrail)

    assert findings_for(findings, rules.POTENTIALLY_UNUSED_ACCESS, "alice") == []


def test_cloudtrail_activity_in_unrelated_service_does_not_suppress(normalized, last_accessed):
    # charlie's only access is S3 — CloudTrail activity in an unrelated
    # service (e.g. iam) must not be treated as covering his S3 grant.
    charlie_id = next(u for u in normalized["users"] if u["name"] == "charlie")["id"]
    cloudtrail = cloudtrail_with_event(charlie_id, "iam.amazonaws.com")

    findings = rules.potentially_unused_access(normalized, last_accessed, cloudtrail)

    assert findings_for(findings, rules.POTENTIALLY_UNUSED_ACCESS, "charlie")


def test_finding_names_both_sources_as_consulted(normalized, last_accessed):
    findings = rules.potentially_unused_access(normalized, last_accessed, {"events": []})
    charlie_findings = findings_for(findings, rules.POTENTIALLY_UNUSED_ACCESS, "charlie")
    assert charlie_findings
    for finding in charlie_findings:
        assert finding["evidence_window"]["sources_consulted"] == [
            "iam_last_accessed",
            "cloudtrail_event_history",
        ]
