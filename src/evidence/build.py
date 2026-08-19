"""Evidence package assembly for the AI layer.

Packages already-collected evidence per principal — it does not compute
anything new. Findings are deliberately not embedded here; they stay in
output/findings/findings.json and are joined by principal id later. This
module never decides whether something is a problem, only assembles what
already exists.
"""

import networkx as nx

from src.graph.build import CAN_ASSUME

BASELINE_EVIDENCE_LIMITATIONS = (
    "The POC covers a single AWS account only.",
    "IAM Last Accessed represents access attempts, including denied attempts, "
    "not only successful calls, and does not report unauthenticated requests.",
    "IAM Last Accessed has service/action historical tracking limitations; "
    "absence of a result does not prove an action was never used.",
    "CloudTrail Event History never includes data events such as s3:GetObject.",
    "The POC does not implement the complete AWS authorization evaluation model.",
    "Permissions boundaries, session policies, and organization-level (SCP) "
    "policies are outside the intended analysis scope.",
    "The relationship graph is local to this run, not a persistent graph database.",
    "AI output is advisory and must remain grounded in the evidence supplied here.",
)


def _configured_access(normalized: dict, principal_id: str) -> list[dict]:
    policy_by_id = {p["id"]: p for p in normalized["policies"]}
    permissions_by_policy: dict[str, list[dict]] = {}
    for permission in normalized["permissions"]:
        permissions_by_policy.setdefault(permission["policy_id"], []).append(permission)

    entries = []
    for attachment in normalized["attachments"]:
        if attachment["principal_id"] != principal_id:
            continue
        policy = policy_by_id[attachment["policy_id"]]
        entry = {
            "policy": policy["name"],
            "attachment_type": attachment["attachment_type"],
            "permissions": [
                {"effect": p["effect"], "actions": p["actions"], "resources": p["resources"]}
                for p in permissions_by_policy.get(policy["id"], [])
            ],
        }
        if attachment["attachment_type"] == "group_inherited":
            entry["source_group_name"] = attachment["source_group_name"]
        entries.append(entry)
    return entries


def _relationships(graph: nx.DiGraph, principal_id: str) -> list[dict]:
    """CAN_ASSUME edges reachable from this principal, including downstream
    hops it doesn't originate (e.g. DeveloperRole -> AdminRole shows up in
    alice's package too, since her chain passes through it)."""
    can_assume_edges = [(u, v) for u, v, data in graph.edges(data=True) if data.get("relationship") == CAN_ASSUME]
    can_assume_graph = nx.DiGraph()
    can_assume_graph.add_nodes_from(graph.nodes)
    can_assume_graph.add_edges_from(can_assume_edges)

    if principal_id not in can_assume_graph:
        return []

    reachable = {principal_id} | nx.descendants(can_assume_graph, principal_id)
    return [
        {
            "from": graph.nodes[u]["name"],
            "relationship": CAN_ASSUME,
            "to": graph.nodes[v]["name"],
        }
        for u, v in can_assume_graph.edges()
        if u in reachable
    ]


def _observed_activity(cloudtrail: dict, principal_id: str) -> dict:
    events = [
        {
            "event_name": event["EventName"],
            "event_source": event["EventSource"],
            "timestamp": event["EventTime"],
        }
        for event in cloudtrail.get("events", [])
        if event.get("attributed_principal_arn") == principal_id
    ]
    return {
        "evidence_window": cloudtrail.get("evidence_window", {}),
        "events": events,
    }


def _last_accessed(last_accessed: dict, principal_id: str) -> list[dict]:
    entry = last_accessed.get(principal_id)
    if entry is None:
        return []
    return [
        {"service": service["ServiceNamespace"], "last_authenticated": service.get("LastAuthenticated")}
        for service in entry["services_last_accessed"]
    ]


def _evidence_limitations(cloudtrail: dict, region: str, analyzer_data: dict) -> list[str]:
    window = cloudtrail.get("evidence_window", {})
    analyzer_types = sorted({a["type"] for a in analyzer_data.get("analyzers", [])}) or ["none active"]
    return [
        f"CloudTrail Event History covers management events only, region {cloudtrail.get('region', region)}, "
        f"the last {window.get('lookback_days', 'unknown')} days "
        f"({window.get('start_time')} to {window.get('end_time')}).",
        f"Access Analyzer evidence reflects external-access analyzers only (types observed: "
        f"{', '.join(analyzer_types)}); the paid unused-access analyzer type is never queried.",
        *BASELINE_EVIDENCE_LIMITATIONS,
    ]


def build_evidence_package(
    normalized: dict,
    graph: nx.DiGraph,
    last_accessed: dict,
    cloudtrail: dict,
    analyzer_data: dict,
    region: str,
) -> dict:
    """Build one evidence package per normalized user and role. Groups are excluded."""
    limitations = _evidence_limitations(cloudtrail, region, analyzer_data)
    analyzer_findings = analyzer_data.get("findings", [])

    packages = {}
    for principal in normalized["users"] + normalized["roles"]:
        packages[principal["id"]] = {
            "principal": {"id": principal["id"], "name": principal["name"], "type": principal["type"]},
            "configured_access": _configured_access(normalized, principal["id"]),
            "relationships": _relationships(graph, principal["id"]),
            "observed_activity": _observed_activity(cloudtrail, principal["id"]),
            "last_accessed": _last_accessed(last_accessed, principal["id"]),
            "analyzer_findings": analyzer_findings,
            "evidence_limitations": limitations,
        }

    return {"packages": packages}
