"""IAM configuration collection.

GetAccountAuthorizationDetails returns users, groups, roles and policies
together with their relationships and policy documents, in one paginated
operation. Preferred over enumerating principals and querying each one's
policies separately, which would issue hundreds of requests for the same data
and put avoidable load on an account we do not own.
"""

import json
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from src.util.status import CollectionStatus, failed, ok

SOURCE = "iam_configuration"

SECTIONS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


def collect(session: boto3.Session) -> tuple[dict, CollectionStatus]:
    """Fetch the full IAM authorization snapshot.

    Returns the raw response merged across pages, untouched apart from the
    merge. Normalization happens elsewhere.
    """
    iam = session.client("iam")
    merged: dict[str, list] = {section: [] for section in SECTIONS}
    pages = 0

    try:
        # Paginate to completion. Stopping early — or on an empty page, which
        # can occur mid-sequence — yields silently incomplete data.
        for page in iam.get_paginator("get_account_authorization_details").paginate():
            pages += 1
            for section in SECTIONS:
                merged[section].extend(page.get(section, []))
    except (ClientError, BotoCoreError) as exc:
        return {}, failed(SOURCE, str(exc))

    counts = {section: len(merged[section]) for section in SECTIONS}
    return merged, ok(SOURCE, counts, pages)


def decode_policy_document(document: str | dict) -> dict:
    """Return a policy document as a dict.

    The API contract specifies URL-encoded documents, but boto3 decodes and
    parses them automatically. Check the type — blindly decoding an
    already-decoded document corrupts it.
    """
    if isinstance(document, dict):
        return document
    return json.loads(unquote(document))


def describe_document_encoding(raw: dict) -> str:
    """Report which form this account's policy documents arrive in.

    Diagnostic only. Run once so the answer is recorded rather than assumed.
    """
    for policy in raw.get("Policies", []):
        for version in policy.get("PolicyVersionList", []):
            document = version.get("Document")
            if document is not None:
                kind = type(document).__name__
                return f"policy documents arrive as {kind} (already decoded)" \
                    if isinstance(document, dict) else \
                    f"policy documents arrive as {kind} (URL-encoded, decode required)"
    return "no policy documents found to inspect"
