"""IAM Service/Action Last Accessed collection.

One async job per principal: GenerateServiceLastAccessedDetails returns a
JobId, GetServiceLastAccessedDetails is polled until the job leaves
IN_PROGRESS. This operation has no boto3 paginator model (unlike
get_account_authorization_details) — pagination is manual via the response's
IsTruncated/Marker fields once the job has completed.

The poll loop here waits seconds for AWS to finish computing an already
generated job. That is not the ~4-hour last-accessed propagation delay
CLAUDE.md forbids working around — recent activity can still be entirely
absent from a completed job's results, and that is an expected, valid
result, not a collection failure.

Each principal gets its own CollectionStatus, so one throttled or denied
principal does not mark the whole batch as failed.
"""

import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "last_accessed"

POLL_INTERVAL_SECONDS = 2
MAX_POLL_ATTEMPTS = 60  # ~2 minutes, for job completion only


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


def collect(session: boto3.Session, principals: list[dict]) -> tuple[dict, list[CollectionStatus]]:
    """Fetch service last-accessed evidence for each given principal.

    `principals` is a list of {"id": arn, "name": ..., "type": "user"/"role"}
    drawn from the normalized output. Returns evidence keyed by principal id,
    plus one CollectionStatus per principal — a principal with zero services
    is a successful, empty result, not a failure.
    """
    iam = session.client("iam")
    data: dict[str, dict] = {}
    statuses: list[CollectionStatus] = []

    for principal in principals:
        source = _principal_source(principal)
        try:
            job_id = iam.generate_service_last_accessed_details(Arn=principal["id"])["JobId"]
            services = _fetch_services_last_accessed(iam, job_id)
        except (ClientError, BotoCoreError, RuntimeError, TimeoutError) as exc:
            statuses.append(failed(source, str(exc)))
            continue

        data[principal["id"]] = {
            "principal_name": principal["name"],
            "principal_type": principal["type"],
            "services_last_accessed": services,
        }
        statuses.append(ok(source, {"services": len(services)}))

    return data, statuses
