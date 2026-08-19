"""IAM Access Analyzer external-access findings collection.

Read-only inspection of an analyzer that already exists in the account. This
code never creates or modifies an analyzer, and never queries the paid
unused-access analyzer types (ACCOUNT_UNUSED_ACCESS / ORGANIZATION_UNUSED_ACCESS)
— only the external-access types (ACCOUNT / ORGANIZATION). The unused-access
types are billed per principal per month and must stay off.

An existing external-access analyzer returning zero findings is a
successful, empty result — not a failure.
"""

from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "access_analyzer"

EXTERNAL_ACCESS_TYPES = ("ACCOUNT", "ORGANIZATION")


def collect(session) -> tuple[dict, CollectionStatus]:
    """Fetch findings from every ACTIVE external-access analyzer in the account."""
    client = session.client("accessanalyzer")

    try:
        analyzers = [
            analyzer
            for page in client.get_paginator("list_analyzers").paginate()
            for analyzer in page.get("analyzers", [])
            if analyzer.get("type") in EXTERNAL_ACCESS_TYPES and analyzer.get("status") == "ACTIVE"
        ]

        findings = []
        for analyzer in analyzers:
            for page in client.get_paginator("list_findings").paginate(analyzerArn=analyzer["arn"]):
                findings.extend(page.get("findings", []))
    except (ClientError, BotoCoreError) as exc:
        return {}, failed(SOURCE, str(exc))

    data = {
        "analyzers": [{"arn": a["arn"], "name": a["name"], "type": a["type"], "status": a["status"]} for a in analyzers],
        "findings": findings,
    }
    return data, ok(SOURCE, {"analyzers": len(analyzers), "findings": len(findings)})
