"""Deterministic security rules over the common model.

Deny precedence is a correctness requirement, not a rule of its own, so it
lives here as the shared `_is_denied` check used by every rule below.
Indirect privilege paths need graph traversal and live in their own module.

Findings are code-derived and reproducible: the same normalized input and
usage evidence always produce the same findings.
"""

import fnmatch

BROAD_PERMISSION = "broad_permission"
ADMINISTRATIVE_ACCESS = "administrative_access"
POTENTIALLY_UNUSED_ACCESS = "potentially_unused_access"

WILDCARD = "*"


def _patterns_cover(covering_patterns: list[str], covered_patterns: list[str]) -> bool:
    """True if every pattern in `covered_patterns` is matched by some pattern in `covering_patterns`.

    Patterns are compared as literal strings against each other's wildcard
    shape — no action/resource is ever expanded. A narrow Deny such as
    `iam:GetCredentialReport` does not cover a `*` Allow; only an equally or
    more permissive Deny pattern does.
    """
    for covered in covered_patterns:
        if not any(fnmatch.fnmatchcase(covered, covering) for covering in covering_patterns):
            return False
    return True


def _is_denied(policy_permissions: list[dict], allow_permission: dict) -> bool:
    """True if a Deny statement in the same policy fully cancels this Allow."""
    for other in policy_permissions:
        if other["effect"] != "Deny":
            continue
        if _patterns_cover(other["actions"], allow_permission["actions"]) and _patterns_cover(
            other["resources"], allow_permission["resources"]
        ):
            return True
    return False


def _effective_allows(policy_permissions: list[dict]) -> list[dict]:
    return [p for p in policy_permissions if p["effect"] == "Allow" and not _is_denied(policy_permissions, p)]


def _is_full_wildcard(permission: dict) -> bool:
    return WILDCARD in permission["actions"] and WILDCARD in permission["resources"]


def _index_by_id(records: list[dict]) -> dict:
    return {r["id"]: r for r in records}


def _permissions_by_policy(permissions: list[dict]) -> dict[str, list[dict]]:
    by_policy: dict[str, list[dict]] = {}
    for permission in permissions:
        by_policy.setdefault(permission["policy_id"], []).append(permission)
    return by_policy


def _attribution(attachment: dict) -> dict:
    attribution = {"attachment_type": attachment["attachment_type"]}
    if attachment["attachment_type"] == "group_inherited":
        attribution["source_group_name"] = attachment["source_group_name"]
    return attribution


def _access_description(attachment: dict) -> str:
    if attachment["attachment_type"] == "group_inherited":
        return f"the {attachment['source_group_name']} group"
    if attachment["attachment_type"] == "direct_attached":
        return "a directly attached policy"
    return "an inline policy"


def _principal(identity_by_id: dict, principal_id: str) -> dict:
    record = identity_by_id[principal_id]
    return {"id": record["id"], "name": record["name"], "type": record["type"]}


def broad_permission_and_administrative_access(normalized: dict) -> list[dict]:
    """Flag every effectively-Allow permission granting Action=*, Resource=*.

    Emits both `broad_permission` and `administrative_access` for the same
    match — they are separate deterministic rules that may legitimately
    identify the same access, each with its own attribution.
    """
    identity_by_id = _index_by_id(normalized["users"] + normalized["groups"] + normalized["roles"])
    policy_by_id = _index_by_id(normalized["policies"])
    permissions_by_policy = _permissions_by_policy(normalized["permissions"])

    findings = []
    for attachment in normalized["attachments"]:
        policy = policy_by_id[attachment["policy_id"]]
        policy_permissions = permissions_by_policy.get(policy["id"], [])
        principal = _principal(identity_by_id, attachment["principal_id"])
        access_description = _access_description(attachment)

        for permission in _effective_allows(policy_permissions):
            if not _is_full_wildcard(permission):
                continue

            base = {
                "principal": principal,
                "policy_id": policy["id"],
                "attribution": _attribution(attachment),
            }
            findings.append(
                {
                    **base,
                    "rule": BROAD_PERMISSION,
                    "detail": (
                        f"{principal['name']} holds a policy granting unrestricted access "
                        f"(Action=*, Resource=*) via {access_description}."
                    ),
                }
            )
            findings.append(
                {
                    **base,
                    "rule": ADMINISTRATIVE_ACCESS,
                    "detail": (
                        f"{principal['name']} has administrative access (Action=*, Resource=*) "
                        f"via {access_description}."
                    ),
                }
            )

    return findings


def _service_of(action: str) -> str | None:
    """Return the service namespace an action belongs to, or None for `*`."""
    if action == WILDCARD:
        return None
    return action.split(":", 1)[0]


def _services_granted(policy_permissions: list[dict]) -> set[str] | None:
    """Services an effective Allow set covers. None means "any service"."""
    services: set[str] = set()
    for permission in _effective_allows(policy_permissions):
        for action in permission["actions"]:
            service = _service_of(action)
            if service is None:
                return None
            services.add(service)
    return services


def _last_accessed_activity(last_accessed_entry: dict | None, services: set[str] | None) -> bool:
    if last_accessed_entry is None:
        return False
    entries = last_accessed_entry["services_last_accessed"]
    if services is None:
        return any(e.get("LastAuthenticated") for e in entries)
    last_authenticated_by_service = {e["ServiceNamespace"]: e.get("LastAuthenticated") for e in entries}
    return any(last_authenticated_by_service.get(service) for service in services)


def _cloudtrail_services_by_principal(cloudtrail: dict) -> dict[str, set[str]]:
    """Service namespaces each principal was observed calling in CloudTrail.

    Attribution (event -> principal) already happened at collection time
    (src/aws/cloudtrail_collector.py); this only reduces attributed events
    down to service names, at the same granularity as last-accessed.
    """
    by_principal: dict[str, set[str]] = {}
    for event in cloudtrail.get("events", []):
        principal_arn = event.get("attributed_principal_arn")
        if principal_arn is None:
            continue
        service = event["EventSource"].split(".", 1)[0]
        by_principal.setdefault(principal_arn, set()).add(service)
    return by_principal


def _cloudtrail_activity(principal_services: set[str], services: set[str] | None) -> bool:
    if services is None:
        return bool(principal_services)
    return bool(principal_services & services)


def potentially_unused_access(normalized: dict, last_accessed: dict, cloudtrail: dict) -> list[dict]:
    """Flag access with no corresponding activity in the collected evidence.

    Users and roles only — groups have no last-accessed data and can't be
    CloudTrail principals. Activity in either iam_last_accessed or
    cloudtrail_event_history suppresses the finding; the two are never
    reconciled by preferring whichever is non-empty, only combined with OR.
    """
    identity_by_id = _index_by_id(normalized["users"] + normalized["groups"] + normalized["roles"])
    policy_by_id = _index_by_id(normalized["policies"])
    permissions_by_policy = _permissions_by_policy(normalized["permissions"])
    cloudtrail_services_by_principal = _cloudtrail_services_by_principal(cloudtrail)

    findings = []
    for attachment in normalized["attachments"]:
        principal = _principal(identity_by_id, attachment["principal_id"])
        if principal["type"] not in ("user", "role"):
            continue

        policy = policy_by_id[attachment["policy_id"]]
        policy_permissions = permissions_by_policy.get(policy["id"], [])
        services = _services_granted(policy_permissions)
        if services is not None and not services:
            continue  # policy grants no effective Allow actions at all

        last_accessed_entry = last_accessed.get(principal["id"])
        principal_cloudtrail_services = cloudtrail_services_by_principal.get(principal["id"], set())
        if _last_accessed_activity(last_accessed_entry, services) or _cloudtrail_activity(
            principal_cloudtrail_services, services
        ):
            continue

        access_description = _access_description(attachment)
        findings.append(
            {
                "rule": POTENTIALLY_UNUSED_ACCESS,
                "principal": principal,
                "policy_id": policy["id"],
                "attribution": _attribution(attachment),
                "evidence_window": {
                    "sources_consulted": ["iam_last_accessed", "cloudtrail_event_history"],
                    "note": (
                        "Neither source shows activity for this access. CloudTrail Event "
                        "History covers management events only, within its available "
                        "lookback window; data events such as s3:GetObject are never "
                        "included."
                    ),
                },
                "detail": (
                    f"No corresponding activity observed in the collected evidence for "
                    f"{principal['name']}'s access via {access_description} ({policy['name']})."
                ),
            }
        )

    return findings


def run_all(normalized: dict, last_accessed: dict, cloudtrail: dict) -> list[dict]:
    return broad_permission_and_administrative_access(normalized) + potentially_unused_access(
        normalized, last_accessed, cloudtrail
    )
