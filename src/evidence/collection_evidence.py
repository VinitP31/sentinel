"""Collection evidence: a provider-neutral record of what a collector run
actually gathered.

Built only from data src/main.py::run_pipeline and
src/vcenter/pipeline.py::run_vcenter_pipeline already collect and already
hold in memory at the point they call these functions - no new provider
call is made here, and no field is invented that the source data doesn't
already contain.

This is an internal artifact (collection_evidence.json). Its only intended
consumer is src/evidence/evidence_report.py, which renders it into the
user-facing Collection Evidence PDF - the JSON itself is never surfaced as
a user-facing or agent-facing output.

Never includes credentials of any kind: no password, API key, access key,
secret key, REST session id, or SOAP session/service-instance object. The
`identity` section is limited to what was already safe to print at the CLI
authentication stage (AWS) or the already-established REST base URL
(vCenter) - never anything read from an environment variable named
*_PASSWORD or *_SECRET.
"""

from datetime import datetime, timezone

from src.util.status import CollectionStatus

PROVIDER_AWS = "aws"
PROVIDER_VCENTER = "vcenter"

_NORMALIZED_KEYS = ("users", "groups", "roles", "policies", "permissions", "attachments", "memberships")


def _statuses_as_dicts(statuses: list[CollectionStatus]) -> list[dict]:
    return [status.as_dict() for status in statuses]


def _normalized_counts(normalized: dict) -> dict:
    return {key: len(normalized.get(key, [])) for key in _NORMALIZED_KEYS}


def build_aws_collection_evidence(
    identity: dict,
    raw_iam: dict,
    normalized: dict,
    last_accessed_data: dict,
    cloudtrail_data: dict,
    analyzer_data: dict,
    statuses: list[CollectionStatus],
) -> dict:
    """Assemble AWS collection evidence from data already collected by
    src/main.py::run_pipeline (raw_iam, normalized, last_accessed_data,
    cloudtrail_data, analyzer_data, statuses are all already local variables
    there before this is called)."""
    last_accessed_records = [
        {"principal_id": principal_id, **principal_data} for principal_id, principal_data in last_accessed_data.items()
    ]
    analyzers = analyzer_data.get("analyzers", [])
    findings = analyzer_data.get("findings", [])

    sections = {
        "iam_configuration": {
            "counts": {
                "users": len(raw_iam.get("UserDetailList", [])),
                "groups": len(raw_iam.get("GroupDetailList", [])),
                "roles": len(raw_iam.get("RoleDetailList", [])),
                "policies": len(raw_iam.get("Policies", [])),
            },
            "records": {
                "users": raw_iam.get("UserDetailList", []),
                "groups": raw_iam.get("GroupDetailList", []),
                "roles": raw_iam.get("RoleDetailList", []),
                "policies": raw_iam.get("Policies", []),
            },
        },
        "last_accessed": {
            "counts": {"principals": len(last_accessed_records)},
            "records": last_accessed_records,
        },
        "cloudtrail": {
            "counts": {"events": len(cloudtrail_data.get("events", []))},
            "region": cloudtrail_data.get("region"),
            "evidence_window": cloudtrail_data.get("evidence_window", {}),
            "records": cloudtrail_data.get("events", []),
        },
        "access_analyzer": {
            "counts": {"analyzers": len(analyzers), "findings": len(findings)},
            "records": {"analyzers": analyzers, "findings": findings},
        },
    }

    return {
        "provider": PROVIDER_AWS,
        "collected_at": datetime.now(timezone.utc),
        "identity": {
            "account_id": identity.get("account_id"),
            "arn": identity.get("arn"),
            "region": identity.get("region"),
        },
        "collection_status": _statuses_as_dicts(statuses),
        "sections": sections,
        "normalized_counts": _normalized_counts(normalized),
    }


def build_vcenter_collection_evidence(
    host: str,
    inventory: dict,
    authorization: dict,
    normalized: dict,
    statuses: list[CollectionStatus],
) -> dict:
    """Assemble vCenter collection evidence from data already collected by
    src/vcenter/pipeline.py::run_vcenter_pipeline (inventory, authorization,
    normalized, statuses are all already local variables there before this
    is called). `host` is the already-established REST base URL
    (session.rest_base_url) - a hostname, never a credential."""
    entity_permissions = authorization.get("entity_permissions", [])
    direct_count = sum(len(entity.get("direct", [])) for entity in entity_permissions)
    inherited_count = sum(len(entity.get("inherited", [])) for entity in entity_permissions)

    sections = {
        "inventory": {
            "counts": {object_type: len(records) for object_type, records in inventory.items()},
            "records": inventory,
        },
        "authorization": {
            "counts": {
                "roles": len(authorization.get("roles", {})),
                "privileges": len(authorization.get("privileges", {})),
                "entities": len(entity_permissions),
                "direct_permissions": direct_count,
                "inherited_permissions": inherited_count,
            },
            "roles": authorization.get("roles", {}),
            "privileges": authorization.get("privileges", {}),
            "entity_permissions": entity_permissions,
        },
    }

    return {
        "provider": PROVIDER_VCENTER,
        "collected_at": datetime.now(timezone.utc),
        "identity": {"host": host},
        "collection_status": _statuses_as_dicts(statuses),
        "sections": sections,
        "normalized_counts": _normalized_counts(normalized),
    }
