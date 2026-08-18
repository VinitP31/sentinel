"""Authentication and account verification.

This is the only module that differs between auditing an owned account and
auditing a customer's account. In the POC it reads local credentials. A
production connector would assume a read-only role in the target account and
receive temporary credentials instead.

Everything downstream is identical either way, which is why this stays isolated.
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src import config


class AuthError(RuntimeError):
    """Authentication failed, or the wrong account is authenticated."""


def get_session() -> boto3.Session:
    return boto3.Session(
        profile_name=config.AWS_PROFILE_NAME,
        region_name=config.AWS_REGION,
    )


def verify_identity(session: boto3.Session) -> dict[str, str]:
    """Confirm who we are and which account, before collecting anything.

    GetCallerIdentity requires no IAM permission, so a failure here means the
    credentials themselves are missing, expired or malformed — never a
    permissions problem. That makes it a clean first check.
    """
    try:
        identity = session.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as exc:
        raise AuthError(f"Could not authenticate to AWS: {exc}") from exc

    account = identity["Account"]

    if config.EXPECTED_ACCOUNT_ID and account != config.EXPECTED_ACCOUNT_ID:
        raise AuthError(
            f"Authenticated account {account} does not match "
            f"EXPECTED_ACCOUNT_ID {config.EXPECTED_ACCOUNT_ID}. Aborting."
        )

    return {
        "account_id": account,
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
        "region": session.region_name,
    }
