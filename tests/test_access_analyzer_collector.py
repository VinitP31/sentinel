"""Access Analyzer external-access collection tests.

No live AWS calls — the boto3 accessanalyzer client is mocked. Covers
type/status filtering (external-access only, ACTIVE only) and the
empty-findings-is-success case, matching the planted test-account scenario.
"""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.aws import access_analyzer_collector as aac


def make_session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def analyzer(name, type_, status="ACTIVE", arn=None):
    return {"arn": arn or f"arn:aws:access-analyzer:us-east-1:123456789012:analyzer/{name}", "name": name, "type": type_, "status": status}


def test_active_external_access_analyzer_with_empty_findings_is_success():
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: (
        [{"analyzers": [analyzer("POC-External-Access", "ACCOUNT")]}]
        if "analyzerArn" not in kwargs
        else [{"findings": []}]
    )

    data, status = aac.collect(make_session(client))

    assert status.succeeded
    assert status.record_counts == {"analyzers": 1, "findings": 0}
    assert data["findings"] == []
    assert data["analyzers"][0]["name"] == "POC-External-Access"


def test_findings_collected_when_present():
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: (
        [{"analyzers": [analyzer("POC-External-Access", "ACCOUNT")]}]
        if "analyzerArn" not in kwargs
        else [{"findings": [{"id": "f1"}, {"id": "f2"}]}]
    )

    data, status = aac.collect(make_session(client))

    assert status.record_counts == {"analyzers": 1, "findings": 2}
    assert len(data["findings"]) == 2


def test_unused_access_analyzer_type_excluded():
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: (
        [
            {
                "analyzers": [
                    analyzer("POC-External-Access", "ACCOUNT"),
                    analyzer("SomeUnusedAccessAnalyzer", "ACCOUNT_UNUSED_ACCESS"),
                ]
            }
        ]
        if "analyzerArn" not in kwargs
        else [{"findings": []}]
    )

    data, status = aac.collect(make_session(client))

    assert status.record_counts["analyzers"] == 1
    assert all(a["type"] != "ACCOUNT_UNUSED_ACCESS" for a in data["analyzers"])


def test_inactive_analyzer_excluded():
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: (
        [{"analyzers": [analyzer("Disabled", "ACCOUNT", status="DISABLED")]}] if "analyzerArn" not in kwargs else []
    )

    data, status = aac.collect(make_session(client))

    assert data["analyzers"] == []
    assert status.record_counts == {"analyzers": 0, "findings": 0}


def test_no_analyzers_at_all_is_success_not_failure():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"analyzers": []}]

    data, status = aac.collect(make_session(client))

    assert status.succeeded
    assert data == {"analyzers": [], "findings": []}


def test_access_denied_reported_as_failure():
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListAnalyzers"
    )

    data, status = aac.collect(make_session(client))

    assert not status.succeeded
    assert "not authorized" in status.error
    assert data == {}
