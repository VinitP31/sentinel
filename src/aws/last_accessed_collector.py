"""IAM Service/Action Last Accessed collection.

One async job per principal: GenerateServiceLastAccessedDetails returns a
JobId, GetServiceLastAccessedDetails is polled until the job leaves
IN_PROGRESS. This operation has no boto3 paginator model (unlike
get_account_authorization_details) — pagination is manual via the response's
IsTruncated/Marker fields once the job has completed.

The poll loop here waits seconds for AWS to finish computing an already
generated job. That is not the ~4-hour last-accessed propagation delay,
which must never be worked around — recent activity can still be entirely
absent from a completed job's results, and that is an expected, valid
result, not a collection failure.

Each principal gets its own CollectionStatus, so one throttled or denied
principal does not mark the whole batch as failed.

Principals are independent AWS jobs — one principal's generate/poll/paginate
sequence never depends on another's — so collect() runs them through a
small bounded thread pool (MAX_WORKERS) instead of one at a time. A single
boto3 IAM client is shared across workers: botocore clients are safe for
concurrent use from multiple threads for making calls (each call is a
self-contained request over the client's connection pool), so this mirrors
the same shared-client, bounded-worker-count shape already used for AI
explanations (src/ai/explain.py) rather than inventing a new pattern or a
per-thread client/session.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "last_accessed"

POLL_INTERVAL_SECONDS = 2
MAX_POLL_ATTEMPTS = 60  # ~2 minutes, for job completion only
MAX_WORKERS = 5


def _principal_source(principal: dict) -> str:
    return f"{SOURCE}:{principal['type']}:{principal['name']}"


def _fetch_services_last_accessed(iam, job_id: str) -> list[dict]:
    """Poll a last-accessed job to completion, then page through results."""
    services: list[dict] = []
    marker = None
    attempts = 0

    while True:
        kwargs = {"JobId": job_id}
        if marker:
            kwargs["Marker"] = marker
        response = iam.get_service_last_accessed_details(**kwargs)
        status = response["JobStatus"]

        if status == "IN_PROGRESS":
            attempts += 1
            if attempts >= MAX_POLL_ATTEMPTS:
                raise TimeoutError(f"job {job_id} still IN_PROGRESS after {attempts} polls")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if status == "FAILED":
            raise RuntimeError(response.get("Error", {}).get("Message", "job failed"))

        services.extend(response.get("ServicesLastAccessed", []))
        if not response.get("IsTruncated"):
            return services
        marker = response["Marker"]


def _collect_one(iam, principal: dict) -> tuple[str, dict | None, CollectionStatus]:
    """The exact existing per-principal sequence (generate -> poll -> paginate),
    unchanged — only ever called from a worker thread, never mutates any
    state shared with other principals, and never raises: any failure here
    becomes that principal's own CollectionStatus so it can never abort
    (or be blamed on) another principal's collection.
    """
    source = _principal_source(principal)
    try:
        job_id = iam.generate_service_last_accessed_details(Arn=principal["id"])["JobId"]
        services = _fetch_services_last_accessed(iam, job_id)
    except (ClientError, BotoCoreError, RuntimeError, TimeoutError) as exc:
        return principal["id"], None, failed(source, str(exc))

    principal_data = {
        "principal_name": principal["name"],
        "principal_type": principal["type"],
        "services_last_accessed": services,
    }
    return principal["id"], principal_data, ok(source, {"services": len(services)})


def collect(session: boto3.Session, principals: list[dict]) -> tuple[dict, list[CollectionStatus]]:
    """Fetch service last-accessed evidence for each given principal.

    `principals` is a list of {"id": arn, "name": ..., "type": "user"/"role"}
    drawn from the normalized output. Returns evidence keyed by principal id,
    plus one CollectionStatus per principal — a principal with zero services
    is a successful, empty result, not a failure.

    Principals are processed through a bounded thread pool (MAX_WORKERS) —
    each principal's job is independent, so this only changes *when* each
    one runs, never what is collected. Results are placed back by the
    principal's original list index, not completion order, so the returned
    statuses list stays in the same order as `principals` regardless of
    which job happens to finish first.
    """
    iam = session.client("iam")
    data: dict[str, dict] = {}
    results: list[tuple[str, dict | None, CollectionStatus] | None] = [None] * len(principals)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_index = {executor.submit(_collect_one, iam, principal): i for i, principal in enumerate(principals)}
        for future in as_completed(future_to_index):
            results[future_to_index[future]] = future.result()

    statuses: list[CollectionStatus] = []
    for principal_id, principal_data, status in results:
        statuses.append(status)
        if principal_data is not None:
            data[principal_id] = principal_data

    return data, statuses
