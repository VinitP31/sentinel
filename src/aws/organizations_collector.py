"""AWS Organizations account discovery.

Lists every account visible to this session via ListAccounts — read-only,
no filtering, no judgment about which accounts should be audited. That
decision belongs to whoever calls this collector, not to collection itself.

A standalone (non-Organizations) account is a distinct, valid outcome, not
a permissions failure: AWSOrganizationsNotInUseException is reported as its
own CollectionStatus.error text rather than folded into the generic
ClientError/BotoCoreError branch below.
"""

from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "organizations"


def collect(session) -> tuple[dict, CollectionStatus]:
    """Fetch every account in the organization this session's identity can see.

    Returns {"accounts": [{"id", "name", "email", "state"}, ...]}, in
    whatever order ListAccounts returns them, with no ACTIVE/state
    filtering applied here.
    """
    client = session.client("organizations")
    accounts = []
    pages = 0

    try:
        for page in client.get_paginator("list_accounts").paginate():
            pages += 1
            accounts.extend(page.get("Accounts", []))
    except client.exceptions.AWSOrganizationsNotInUseException as exc:
        return {}, failed(SOURCE, f"not an Organizations account: {exc}")
    except (ClientError, BotoCoreError) as exc:
        return {}, failed(SOURCE, str(exc))

    data = {
        "accounts": [
            {"id": a["Id"], "name": a["Name"], "email": a["Email"], "state": a["State"]}
            for a in accounts
        ]
    }
    return data, ok(SOURCE, {"accounts": len(data["accounts"])}, pages)
