"""Service last-accessed collection tests.

No live AWS calls — the boto3 iam client is mocked. Covers: job polling to
completion, manual Marker-based pagination (no paginator model exists for
this operation), per-principal failure isolation, and empty-result-is-not-
failure.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.aws import last_accessed_collector as lac

ALICE = {"id": "arn:aws:iam::123456789012:user/alice", "name": "alice", "type": "user"}
BOB = {"id": "arn:aws:iam::123456789012:user/bob", "name": "bob", "type": "user"}


def make_session(iam_client):
    session = MagicMock()
    session.client.return_value = iam_client
    return session


@pytest.fixture(autouse=True)
def no_sleep():
    with patch.object(lac.time, "sleep"):
        yield


def test_successful_collection_single_page():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [{"ServiceNamespace": "s3", "LastAuthenticated": "2026-08-01T00:00:00Z"}],
        "IsTruncated": False,
    }

    data, statuses = lac.collect(make_session(iam), [ALICE])

    assert len(statuses) == 1
    assert statuses[0].succeeded
    assert statuses[0].record_counts == {"services": 1}
    assert data[ALICE["id"]]["services_last_accessed"][0]["ServiceNamespace"] == "s3"


def test_pagination_across_multiple_pages():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.side_effect = [
        {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
            "IsTruncated": True,
            "Marker": "page-2",
        },
        {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [{"ServiceNamespace": "iam"}],
            "IsTruncated": False,
        },
    ]

    data, statuses = lac.collect(make_session(iam), [ALICE])

    assert statuses[0].succeeded
    assert statuses[0].record_counts == {"services": 2}
    services = data[ALICE["id"]]["services_last_accessed"]
    assert {s["ServiceNamespace"] for s in services} == {"s3", "iam"}
    # second call must have carried the Marker forward
    second_call_kwargs = iam.get_service_last_accessed_details.call_args_list[1].kwargs
    assert second_call_kwargs.get("Marker") == "page-2"


def test_job_in_progress_then_completes():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.side_effect = [
        {"JobStatus": "IN_PROGRESS"},
        {"JobStatus": "IN_PROGRESS"},
        {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "s3"}], "IsTruncated": False},
    ]

    data, statuses = lac.collect(make_session(iam), [ALICE])

    assert statuses[0].succeeded
    assert statuses[0].record_counts == {"services": 1}
    assert iam.get_service_last_accessed_details.call_count == 3


def test_empty_services_is_success_not_failure():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [],
        "IsTruncated": False,
    }

    data, statuses = lac.collect(make_session(iam), [BOB])

    assert statuses[0].succeeded
    assert statuses[0].record_counts == {"services": 0}
    assert data[BOB["id"]]["services_last_accessed"] == []


def test_empty_result_does_not_trigger_extra_calls():
    # Empty-but-completed must not trigger extra polling calls.
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [],
        "IsTruncated": False,
    }

    lac.collect(make_session(iam), [BOB])

    assert iam.get_service_last_accessed_details.call_count == 1


def test_one_principal_failure_does_not_affect_another():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.side_effect = [
        ClientError({"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GenerateServiceLastAccessedDetails"),
        {"JobId": "job-ok"},
    ]
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
        "IsTruncated": False,
    }

    data, statuses = lac.collect(make_session(iam), [ALICE, BOB])

    by_source = {s.source: s for s in statuses}
    assert not by_source[lac._principal_source(ALICE)].succeeded
    assert by_source[lac._principal_source(BOB)].succeeded
    assert ALICE["id"] not in data
    assert BOB["id"] in data


def test_job_failed_status_marks_principal_failed():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "FAILED",
        "Error": {"Message": "internal failure"},
    }

    data, statuses = lac.collect(make_session(iam), [ALICE])

    assert not statuses[0].succeeded
    assert "internal failure" in statuses[0].error
    assert ALICE["id"] not in data


def test_stuck_in_progress_times_out_as_failure(monkeypatch):
    monkeypatch.setattr(lac, "MAX_POLL_ATTEMPTS", 2)
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {"JobStatus": "IN_PROGRESS"}

    data, statuses = lac.collect(make_session(iam), [ALICE])

    assert not statuses[0].succeeded
    assert ALICE["id"] not in data
