"""Service last-accessed collection tests.

No live AWS calls — the boto3 iam client is mocked. Covers: job polling to
completion, manual Marker-based pagination (no paginator model exists for
this operation), per-principal failure isolation, empty-result-is-not-
failure, and bounded-concurrency scheduling (worker count, genuine
concurrent execution proven with real synchronization primitives rather
than timing, and deterministic result ordering regardless of completion
order).
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.aws import last_accessed_collector as lac

ALICE = {"id": "arn:aws:iam::123456789012:user/alice", "name": "alice", "type": "user"}
BOB = {"id": "arn:aws:iam::123456789012:user/bob", "name": "bob", "type": "user"}
CHARLIE = {"id": "arn:aws:iam::123456789012:user/charlie", "name": "charlie", "type": "user"}


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
    # Keyed by Arn, not call order — with concurrent workers, which
    # principal's generate call actually executes first is not guaranteed,
    # so the failure must be tied to ALICE's ARN specifically rather than
    # to "whichever call happens first".
    def generate_side_effect(Arn):
        if Arn == ALICE["id"]:
            raise ClientError({"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GenerateServiceLastAccessedDetails")
        return {"JobId": "job-ok"}

    iam = MagicMock()
    iam.generate_service_last_accessed_details.side_effect = generate_side_effect
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


# --- bounded concurrency: worker count, genuine concurrent execution, ------
# --- deterministic ordering, isolated failures ------------------------------


def test_exactly_five_workers_configured():
    assert lac.MAX_WORKERS == 5


def test_collect_uses_a_thread_pool_with_the_configured_worker_count():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [],
        "IsTruncated": False,
    }

    with patch("src.aws.last_accessed_collector.ThreadPoolExecutor", wraps=ThreadPoolExecutor) as spy:
        lac.collect(make_session(iam), [ALICE])

    spy.assert_called_once_with(max_workers=lac.MAX_WORKERS)


def test_multiple_principals_execute_concurrently():
    """A Barrier that requires all three principals' generate calls to
    arrive together — real concurrent execution passes; strictly sequential
    execution (one principal fully finished before the next starts) can
    never gather three simultaneous arrivals and times out instead."""
    barrier = threading.Barrier(3, timeout=2)

    def generate_side_effect(Arn):
        barrier.wait()
        return {"JobId": f"job-{Arn}"}

    iam = MagicMock()
    iam.generate_service_last_accessed_details.side_effect = generate_side_effect
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [],
        "IsTruncated": False,
    }

    data, statuses = lac.collect(make_session(iam), [ALICE, BOB, CHARLIE])

    assert all(s.succeeded for s in statuses)
    assert {ALICE["id"], BOB["id"], CHARLIE["id"]} == set(data)


def test_results_preserve_original_principal_order_regardless_of_completion_order():
    """CHARLIE's job completes first (it signals an Event immediately);
    ALICE's job deliberately waits on that Event before completing, so it
    finishes last. The returned statuses must still be in [ALICE, BOB,
    CHARLIE] input order, not [CHARLIE, BOB, ALICE] completion order."""
    charlie_done = threading.Event()
    job_ids = {ALICE["id"]: "job-alice", BOB["id"]: "job-bob", CHARLIE["id"]: "job-charlie"}

    def generate_side_effect(Arn):
        return {"JobId": job_ids[Arn]}

    def get_side_effect(JobId, Marker=None):
        if JobId == "job-charlie":
            charlie_done.set()
            return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "charlie-svc"}], "IsTruncated": False}
        if JobId == "job-alice":
            assert charlie_done.wait(timeout=2), "charlie's job never signaled completion"
            return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "alice-svc"}], "IsTruncated": False}
        return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "bob-svc"}], "IsTruncated": False}

    iam = MagicMock()
    iam.generate_service_last_accessed_details.side_effect = generate_side_effect
    iam.get_service_last_accessed_details.side_effect = get_side_effect

    data, statuses = lac.collect(make_session(iam), [ALICE, BOB, CHARLIE])

    assert [s.source for s in statuses] == [
        lac._principal_source(ALICE),
        lac._principal_source(BOB),
        lac._principal_source(CHARLIE),
    ]
    assert all(s.succeeded for s in statuses)
    assert data[ALICE["id"]]["services_last_accessed"][0]["ServiceNamespace"] == "alice-svc"
    assert data[CHARLIE["id"]]["services_last_accessed"][0]["ServiceNamespace"] == "charlie-svc"


def test_collect_return_structure_unchanged_with_multiple_principals():
    """collect() must still return (dict keyed by principal id, list of
    CollectionStatus) — the same shape src/main.py already relies on."""
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
        "IsTruncated": False,
    }

    data, statuses = lac.collect(make_session(iam), [ALICE, BOB, CHARLIE])

    assert isinstance(data, dict)
    assert isinstance(statuses, list)
    assert len(statuses) == 3
    assert set(data) == {ALICE["id"], BOB["id"], CHARLIE["id"]}
    for principal_id, record in data.items():
        assert set(record) == {"principal_name", "principal_type", "services_last_accessed"}
