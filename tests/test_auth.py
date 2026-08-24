"""Authentication tests.

No live AWS calls — the boto3 sts client is mocked throughout. Covers
verify_identity's account-mismatch guard and assume_role's session
construction and error handling.
"""

from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from src.aws import auth


def make_session(client, region_name="us-east-1"):
    session = MagicMock()
    session.client.return_value = client
    session.region_name = region_name
    return session


def test_verify_identity_returns_account_and_arn():
    client = MagicMock()
    client.get_caller_identity.return_value = {
        "Account": "957728667615",
        "Arn": "arn:aws:iam::957728667615:user/poc-aws-audit-collector",
        "UserId": "AIDA557ITW7P4H4WVP3FW",
    }

    identity = auth.verify_identity(make_session(client))

    assert identity["account_id"] == "957728667615"
    assert identity["arn"] == "arn:aws:iam::957728667615:user/poc-aws-audit-collector"


def test_verify_identity_raises_on_account_mismatch():
    client = MagicMock()
    client.get_caller_identity.return_value = {
        "Account": "957728667615",
        "Arn": "arn:aws:iam::957728667615:user/poc-aws-audit-collector",
        "UserId": "AIDA557ITW7P4H4WVP3FW",
    }

    with pytest.raises(auth.AuthError):
        auth.verify_identity(make_session(client), expected_account_id="999999999999")


def test_assume_role_returns_session_built_from_temporary_credentials():
    client = MagicMock()
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAFAKEEXAMPLE",
            "SecretAccessKey": "fakeSecretExampleValue",
            "SessionToken": "fakeSessionTokenExampleValue",
        }
    }
    base_session = make_session(client, region_name="us-east-1")

    result = auth.assume_role(base_session, "arn:aws:iam::328865868092:role/AuditReadOnlyRole")

    assert isinstance(result, boto3.Session)
    creds = result.get_credentials().get_frozen_credentials()
    assert creds.access_key == "ASIAFAKEEXAMPLE"
    assert creds.secret_key == "fakeSecretExampleValue"
    assert creds.token == "fakeSessionTokenExampleValue"


def test_assume_role_preserves_base_session_region():
    client = MagicMock()
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAFAKEEXAMPLE",
            "SecretAccessKey": "fakeSecretExampleValue",
            "SessionToken": "fakeSessionTokenExampleValue",
        }
    }
    base_session = make_session(client, region_name="eu-west-1")

    result = auth.assume_role(base_session, "arn:aws:iam::328865868092:role/AuditReadOnlyRole")

    assert result.region_name == "eu-west-1"


def test_assume_role_passes_role_arn_and_session_name():
    client = MagicMock()
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAFAKEEXAMPLE",
            "SecretAccessKey": "fakeSecretExampleValue",
            "SessionToken": "fakeSessionTokenExampleValue",
        }
    }
    base_session = make_session(client)

    auth.assume_role(
        base_session,
        "arn:aws:iam::328865868092:role/AuditReadOnlyRole",
        session_name="custom-session",
        duration_seconds=1800,
    )

    client.assume_role.assert_called_once_with(
        RoleArn="arn:aws:iam::328865868092:role/AuditReadOnlyRole",
        RoleSessionName="custom-session",
        DurationSeconds=1800,
    )


def test_assume_role_failure_becomes_auth_error():
    client = MagicMock()
    client.assume_role.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized to assume role"}}, "AssumeRole"
    )
    base_session = make_session(client)

    with pytest.raises(auth.AuthError) as exc_info:
        auth.assume_role(base_session, "arn:aws:iam::328865868092:role/AuditReadOnlyRole")

    assert "not authorized to assume role" in str(exc_info.value)
