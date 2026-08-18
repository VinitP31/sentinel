"""CloudTrail Event History collection.

One account-wide LookupEvents sweep for the configured lookback window and
region — not one call per principal. LookupEvents has a boto3 paginator
(unlike Stage 5's get_service_last_accessed_details), so pagination follows
the standard "stop only on an absent token" rule.

Event History is 90 days of management events for a single region, and never
includes data events such as s3:GetObject — an API limitation, not a filter
this code applies. No event-name or principal filtering is done here either;
the full window is collected and any subset a rule needs is Stage 6/8's
concern, not collection's.

Each event is attributed to a normalized principal ARN by inspecting its
userIdentity — parsing that structure is CloudTrail-specific and stays in
this layer, per the project's boundary rule. The original CloudTrailEvent
data is kept untouched; attribution is added as an extra field alongside it.
"""

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "cloudtrail_event_history"


def _attributed_principal_arn(user_identity: dict) -> str | None:
    """The normalized-model ARN responsible for this event, if determinable.

    IAMUser events carry the user's own ARN directly. AssumedRole events
    carry an STS session ARN in `arn`, but CloudTrail also provides the
    actual IAM role ARN in `sessionContext.sessionIssuer.arn` — using that
    avoids parsing a session ARN's role name back out ourselves.
    """
    identity_type = user_identity.get("type")
    if identity_type == "IAMUser":
        return user_identity.get("arn")
    if identity_type == "AssumedRole":
        return user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
    return None


def _attribute_event(event: dict) -> dict:
    detail = json.loads(event["CloudTrailEvent"])
    principal_arn = _attributed_principal_arn(detail.get("userIdentity", {}))
    return {**event, "attributed_principal_arn": principal_arn}


def collect(session, lookback_days: int) -> tuple[dict, CollectionStatus]:
    """Fetch the full management-event Event History for the lookback window.

    An empty event list is a successful collection, not a failure — recent
    test activity may simply fall outside what's been indexed yet.
    """
    client = session.client("cloudtrail")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    events = []
    pages = 0
    try:
        for page in client.get_paginator("lookup_events").paginate(StartTime=start_time, EndTime=end_time):
            pages += 1
            events.extend(page.get("Events", []))
    except (ClientError, BotoCoreError) as exc:
        return {}, failed(SOURCE, str(exc))

    data = {
        "region": client.meta.region_name,
        "evidence_window": {
            "start_time": start_time,
            "end_time": end_time,
            "lookback_days": lookback_days,
        },
        "events": [_attribute_event(event) for event in events],
    }
    return data, ok(SOURCE, {"events": len(events)}, pages)
