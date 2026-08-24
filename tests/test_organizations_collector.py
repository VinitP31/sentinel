"""AWS Organizations account discovery tests.

No live AWS calls — the boto3 organizations client is mocked. Covers
pagination, the distinct not-in-an-organization outcome, generic failure,
and that collection never filters by state.
"""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.aws import organizations_collector as oc


def make_session(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def account(id_, name, email, state="ACTIVE"):
    return {"Id": id_, "Name": name, "Email": email, "State": state}


def test_successful_account_collection():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account("957728667615", "Management", "mgmt@example.com")]}
    ]

    data, status = oc.collect(make_session(client))

    assert status.succeeded
    assert status.record_counts == {"accounts": 1}
    assert data["accounts"] == [
        {"id": "957728667615", "name": "Management", "email": "mgmt@example.com", "state": "ACTIVE"}
    ]


def test_account_fields_returned_correctly():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account("328865868092", "PROD", "prod@example.com", state="ACTIVE")]}
    ]

    data, _status = oc.collect(make_session(client))

    entry = data["accounts"][0]
    assert entry["id"] == "328865868092"
    assert entry["name"] == "PROD"
    assert entry["email"] == "prod@example.com"
    assert entry["state"] == "ACTIVE"


def test_pagination_across_multiple_pages():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [account("111111111111", "One", "one@example.com")]},
        {"Accounts": [account("222222222222", "Two", "two@example.com")]},
        {"Accounts": [account("333333333333", "Three", "three@example.com")]},
    ]

    data, status = oc.collect(make_session(client))

    assert status.pages_fetched == 3
    assert status.record_counts == {"accounts": 3}
    assert [a["id"] for a in data["accounts"]] == ["111111111111", "222222222222", "333333333333"]


def test_non_active_accounts_returned_without_filtering():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {
            "Accounts": [
                account("957728667615", "Management", "mgmt@example.com", state="ACTIVE"),
                account("444444444444", "Suspended", "old@example.com", state="SUSPENDED"),
            ]
        }
    ]

    data, status = oc.collect(make_session(client))

    assert status.succeeded
    states = {a["id"]: a["state"] for a in data["accounts"]}
    assert states == {"957728667615": "ACTIVE", "444444444444": "SUSPENDED"}


def test_organizations_not_in_use_is_a_distinct_outcome():
    client = MagicMock()

    class AWSOrganizationsNotInUseException(Exception):
        pass

    client.exceptions.AWSOrganizationsNotInUseException = AWSOrganizationsNotInUseException
    client.get_paginator.return_value.paginate.side_effect = AWSOrganizationsNotInUseException(
        "Your account is not a member of an organization."
    )

    data, status = oc.collect(make_session(client))

    assert not status.succeeded
    assert "not an Organizations account" in status.error
    assert data == {}


def test_generic_client_error_reported_as_failure():
    client = MagicMock()
    client.exceptions.AWSOrganizationsNotInUseException = type(
        "AWSOrganizationsNotInUseException", (Exception,), {}
    )
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListAccounts"
    )

    data, status = oc.collect(make_session(client))

    assert not status.succeeded
    assert "not authorized" in status.error
    assert data == {}
