"""CloudTrail Event History collection tests.

No live AWS calls — the boto3 cloudtrail client is mocked. One account-wide
sweep, not per-principal; covers pagination, empty-success, evidence window
accuracy, and attribution for both IAM-user and assumed-role identities.
"""

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.aws import cloudtrail_collector as ctc


def make_session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def cloudtrail_event(event_name, event_source, user_identity, event_id="evt-1"):
    return {
        "EventId": event_id,
        "EventName": event_name,
        "EventSource": event_source,
        "Username": user_identity.get("userName", ""),
        "CloudTrailEvent": json.dumps({"userIdentity": user_identity}),
    }


def test_single_page_collection():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [
        {"Events": [cloudtrail_event("ListBuckets", "s3.amazonaws.com", {"type": "IAMUser", "arn": "arn:aws:iam::123:user/alice"})]}
    ]

    data, status = ctc.collect(make_session(client), lookback_days=90)

    assert status.succeeded
    assert status.record_counts == {"events": 1}
    assert data["region"] == "us-east-1"
    assert len(data["events"]) == 1


def test_pagination_across_multiple_pages():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [
        {"Events": [cloudtrail_event("ListBuckets", "s3.amazonaws.com", {"type": "IAMUser", "arn": "a"}, "evt-1")]},
        {"Events": [cloudtrail_event("AssumeRole", "sts.amazonaws.com", {"type": "IAMUser", "arn": "a"}, "evt-2")]},
    ]

    data, status = ctc.collect(make_session(client), lookback_days=90)

    assert status.record_counts == {"events": 2}
    assert {e["EventId"] for e in data["events"]} == {"evt-1", "evt-2"}


def test_empty_window_is_successful_not_failure():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [{"Events": []}]

    data, status = ctc.collect(make_session(client), lookback_days=90)

    assert status.succeeded
    assert status.record_counts == {"events": 0}
    assert data["events"] == []


def test_evidence_window_reflects_requested_lookback():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [{"Events": []}]

    data, _ = ctc.collect(make_session(client), lookback_days=30)

    window = data["evidence_window"]
    assert window["lookback_days"] == 30
    assert (window["end_time"] - window["start_time"]).days == 30


def test_evidence_window_records_actual_region():
    client = MagicMock()
    client.meta.region_name = "eu-west-1"
    client.get_paginator.return_value.paginate.return_value = [{"Events": []}]

    data, _ = ctc.collect(make_session(client), lookback_days=90)

    assert data["region"] == "eu-west-1"


def test_iam_user_attribution():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [
        {
            "Events": [
                cloudtrail_event(
                    "ListBuckets",
                    "s3.amazonaws.com",
                    {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice", "userName": "alice"},
                )
            ]
        }
    ]

    data, _ = ctc.collect(make_session(client), lookback_days=90)

    assert data["events"][0]["attributed_principal_arn"] == "arn:aws:iam::123456789012:user/alice"


def test_assumed_role_attribution_uses_session_issuer_role_arn():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    user_identity = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789012:assumed-role/DeveloperRole/alice-session",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "arn": "arn:aws:iam::123456789012:role/DeveloperRole",
            }
        },
    }
    client.get_paginator.return_value.paginate.return_value = [
        {"Events": [cloudtrail_event("AssumeRole", "sts.amazonaws.com", user_identity)]}
    ]

    data, _ = ctc.collect(make_session(client), lookback_days=90)

    assert data["events"][0]["attributed_principal_arn"] == "arn:aws:iam::123456789012:role/DeveloperRole"
    # original identity data must survive untouched
    original = json.loads(data["events"][0]["CloudTrailEvent"])
    assert original["userIdentity"]["arn"] == "arn:aws:sts::123456789012:assumed-role/DeveloperRole/alice-session"


def test_access_denied_is_reported_as_failure_not_empty_success():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "LookupEvents"
    )

    data, status = ctc.collect(make_session(client), lookback_days=90)

    assert not status.succeeded
    assert "not authorized" in status.error
    assert data == {}


def test_unattributable_identity_type_yields_none():
    client = MagicMock()
    client.meta.region_name = "us-east-1"
    client.get_paginator.return_value.paginate.return_value = [
        {"Events": [cloudtrail_event("SomeEvent", "s3.amazonaws.com", {"type": "AWSService"})]}
    ]

    data, _ = ctc.collect(make_session(client), lookback_days=90)

    assert data["events"][0]["attributed_principal_arn"] is None
