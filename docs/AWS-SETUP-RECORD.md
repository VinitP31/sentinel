# AWS POC Setup Record

## Purpose

This document records what was configured in AWS for the IAM security audit POC, what each item is used for, and the test scenarios created.

The goal is to provide a simple reference for understanding the AWS-side setup without requiring the reader to know the implementation details.

The POC has since grown from a single AWS account into a multi-account setup. Section 0 below describes the current multi-account structure. Everything from section 1 onward describes the original single-account test account — that account is now audited as one of the two target accounts (`PROD`), and its test scenarios are unchanged.

---

## 0. Multi-Account Setup (current)

Sentinel audits a Management Account plus a fixed set of target accounts.

### Management account

`957728667615`

The identity used to run an audit (the `poc-aws-audit-collector` local credential chain, or temporary credentials pasted/retrieved through the Streamlit UI) authenticates as this account. From here, Sentinel discovers accounts in the Organization and assumes a role into each target account — it never collects IAM data from the Management Account itself.

### Target accounts

| Label | Account ID |
|---|---|
| PROD | `328865868092` |
| DEV | `587762853586` |

This is the original single-account test account described in section 1 onward, plus a second account (`DEV`) set up the same way. The target account list is fixed configuration (`src/orchestrator.py`), not automatic discovery-driven onboarding — Organizations discovery confirms the accounts exist, it does not decide which accounts get audited.

### Read-only audit role

Each target account has a role named `AuditReadOnlyRole`, trusting the Management Account, holding the same read-only IAM/CloudTrail/Access Analyzer permissions as the original `POC-AWS-IAM-Audit-ReadOnly` policy described in section 2. Sentinel assumes this role once per account per audit run; the resulting temporary credentials are used only for that account's pipeline and are discarded once it finishes.

### Organizations discovery

Sentinel calls AWS Organizations from the Management Account to list accounts in the organization. This is a confirmation/logging step — it does not filter or choose which accounts get audited; that list is the fixed `PROD`/`DEV` configuration above.

### Cross-account role assumption

For each target account, Sentinel exchanges the Management Account session for temporary credentials scoped to that account's `AuditReadOnlyRole`, via `sts:AssumeRole`. Each account gets its own separate temporary session — PROD's credentials are never reused for DEV, and vice versa.

### Local POC credential flow

For local development, the Streamlit UI accepts pasted temporary Management Account credentials, or can retrieve them automatically via the local AWS CLI (`aws sts get-session-token`). Credentials are masked by default, can be manually revealed, and are reused for the remainder of their validity window rather than requesting a new set on every click — the UI clearly distinguishes "reuse the still-valid set" from "explicitly generate a new set." Retrieved credentials are also printed to the local terminal for manual verification during development. This printing behavior is a local-development convenience only, not a production credential-handling recommendation, and is disabled automatically outside interactive local use.

### Test/security scenarios

The scenarios below (section 1 onward) were built for the original single-account test account and are unchanged. They now describe the `PROD` target account specifically. `DEV` is set up as a second, independent target account with the same `AuditReadOnlyRole` trust and read-only permissions, so that Sentinel's multi-account behavior (per-account isolation, combined findings tagged by account) has two real accounts to audit.

---

## 1. AWS Test Account

The POC was originally configured in a single dedicated AWS test account — this is now the `PROD` target account described in section 0.

The primary working region used for the POC is:

- **Region:** `us-east-1` (US East, N. Virginia)

A monthly AWS budget alert was also created as a safety measure.

### Budget

- **Budget:** `POC-Monthly-Cost-Limit`
- **Amount:** `$1/month`
- **Purpose:** Alert us if AWS spending reaches the configured threshold.
- **Important:** This is an alert, not a hard spending limit.

---

## 2. POC Collector User

An IAM user was created for the connector to use when reading the AWS account.

### User

`poc-aws-audit-collector`

### Purpose

This user represents the Management Account identity Sentinel uses locally — either directly (single-account CLI path) or as the base session it assumes `AuditReadOnlyRole` from in each target account (multi-account path).

Console access was disabled.

An access key was created and configured locally for AWS CLI and connector testing.

### Permissions

A customer-managed read-only policy was attached:

`POC-AWS-IAM-Audit-ReadOnly`

The policy provides read access to the AWS areas required by the POC:

- IAM
- CloudTrail
- IAM Access Analyzer

The collector user is not intended to modify AWS resources.

---

## 3. IAM Test Users

Three test users were created to represent different access situations.

### Alice

`alice`

Purpose:

- Represents an active user.
- Has access through a group.
- Has direct permission to assume a role.
- Used to generate real test activity.

### Bob

`bob`

Purpose:

- Represents a user with configured access but no deliberately generated activity.
- Used for the active-vs-inactive comparison.

### Charlie

`charlie`

Purpose:

- Represents a user with permissions attached directly to the user instead of through a group.
- Helps verify that direct permissions are handled separately from group-based permissions.

All three test users have console access disabled.

---

## 4. IAM Groups

Two groups were created.

### Developers

`Developers`

Alice was added to this group.

The group has:

`POC-Developer-S3-ReadOnly`

Purpose:

- Demonstrates access inherited through group membership.

### Auditors

`Auditors`

Bob was added to this group.

The group also has:

`POC-Developer-S3-ReadOnly`

Purpose:

- Gives Bob similar configured S3 access to Alice.
- Allows the POC to compare configured access with actual usage.

---

## 5. S3 Read-Only Test Permission

A customer-managed policy was created:

`POC-Developer-S3-ReadOnly`

The policy provides limited S3 read/list permissions.

It is attached to:

- `Developers`
- `Auditors`
- `Charlie` directly

### Why S3 was included

S3 provides a simple example of a real AWS service permission that can exist without being actively used.

We intentionally did not create an S3 bucket or perform S3 object operations for this POC.

This keeps the test simple and avoids introducing unnecessary S3 usage.

---

## 6. Developer Role

An IAM role was created:

`DeveloperRole`

### Trust

The role trusts:

`alice`

This means Alice is allowed to attempt to assume the role when she also has the corresponding permission.

### Permissions

The role has:

`POC-Developer-Admin-Assume`

This allows the role to assume `AdminRole`.

### Purpose

This creates a role chain:

```text
Alice
  ↓
DeveloperRole
  ↓
AdminRole
```

The connector should be able to discover this as role-assumption relationships.

---

## 7. Admin Role

An IAM role was created:

`AdminRole`

### Trust

The role trusts:

`DeveloperRole`

### Permissions

The role has:

`POC-Admin-Access`

This represents broad administrative access for the test scenario.

### Purpose

This provides an example of indirect privilege:

```text
Alice
  ↓ can assume
DeveloperRole
  ↓ can assume
AdminRole
  ↓
Administrative permissions
```

This is useful for testing whether the audit can identify access that is reached indirectly through role chaining.

---

## 8. Untrusted Role Test

A third test role was created:

`UntrustedRole`

### Trust

The role trusts:

`bob`

### Alice's permission

Alice was given a separate policy:

`POC-UntrustedRole-Assume`

This policy allows Alice to call `sts:AssumeRole` for `UntrustedRole`.

### Why this was created

This is an intentionally mismatched test.

The configuration is:

```text
Alice's permissions
    ↓
Allows AssumeRole → UntrustedRole

UntrustedRole trust policy
    ↓
Trusts Bob
```

Therefore Alice should **not** be treated as having an effective `CAN_ASSUME` relationship to this role.

This tests that the audit does not create a role-assumption relationship simply because an `sts:AssumeRole` permission exists.

Both sides must agree.

---

## 9. Role Assumption Test

Alice was temporarily given an access key so that a real role-assumption action could be generated.

The test performed:

```text
Alice
  ↓
AssumeRole
  ↓
DeveloperRole
```

The role assumption succeeded.

The long-lived Alice access key used for the test was then deleted.

### Why this was done

This provided real usage evidence instead of relying only on configured IAM policies.

---

## 10. CloudTrail

CloudTrail Event History was checked in `us-east-1`.

CloudTrail Event History is being used as the detailed activity source for the POC.

It records recent AWS management activity.

### Verified activity

An actual Alice role-assumption event was found:

- Event: `AssumeRole`
- User: `alice`
- Service: AWS Security Token Service (`sts.amazonaws.com`)
- Target role: `DeveloperRole`
- Session: `alice-poc-session-2`

This confirms that the POC can have both:

```text
Configured access
```

and:

```text
Observed activity
```

to compare.

### What we are not using

For this POC we are not setting up:

- CloudTrail Lake
- Athena
- CloudWatch log delivery
- S3-based CloudTrail log storage
- S3 data-event logging

The normal CloudTrail Event History is sufficient for the management-event activity needed here.

---

## 11. IAM Last Accessed

IAM Last Accessed was tested for Alice at both service and action level.

### Service-level test

A service-level report was generated for Alice.

The result showed:

- S3: no authenticated access observed
- STS: Alice had authenticated/accessed the service

### Action-level test

An action-level report was also generated.

The result included:

```text
STS
  ↓
AssumeRole
```

with the last-accessed information for Alice.

S3 also showed a tracked action:

`ListAllMyBuckets`

but no authenticated usage for Alice.

### Why this matters

This gives the POC a second usage signal:

```text
IAM permissions
+
IAM Last Accessed
+
CloudTrail details
```

The important interpretation is:

**No observed activity does not mean the permission has never been used.**

The information is based on AWS's available tracking data and has processing/tracking limitations.

---

## 12. Access Analyzer

IAM Access Analyzer was enabled in:

`us-east-1`

### Analyzer

`POC-External-Access`

### Type

External access analysis.

### Zone of trust

Current AWS account.

### Status

`ACTIVE`

### Findings

The analyzer was queried and returned:

```text
findings: []
```

This is expected for the current test account because no supported resource was intentionally shared with an external AWS principal.

### Why it was enabled

Access Analyzer is one of the evidence sources for the POC.

The connector should be able to collect external-access findings when they exist and correctly handle an empty result when there are none.

Only external access analysis was enabled for this POC. Internal and unused-access analyzer types were not enabled because they introduce additional charges.

---

## 13. Overall AWS Test Structure

The important access relationships currently configured are:

```text
Alice
  ↓ MEMBER_OF
Developers
  ↓ HAS_POLICY
POC-Developer-S3-ReadOnly
```

```text
Bob
  ↓ MEMBER_OF
Auditors
  ↓ HAS_POLICY
POC-Developer-S3-ReadOnly
```

```text
Charlie
  ↓ HAS_POLICY
POC-Developer-S3-ReadOnly
```

```text
Alice
  ↓ CAN_ASSUME
DeveloperRole
  ↓ CAN_ASSUME
AdminRole
```

And the negative role-assumption test is:

```text
Alice
  ↓ permission allows AssumeRole
UntrustedRole

but

UntrustedRole
  ↓ trusts
Bob
```

Therefore Alice should not have an effective `CAN_ASSUME` relationship to `UntrustedRole`.

---

## 14. Activity vs Configuration Test

The main usage comparison prepared for the POC is:

| User | Configured S3 access | Observed activity |
|---|---|---|
| Alice | Yes | STS/AssumeRole activity observed |
| Bob | Yes | No deliberate activity generated |
| Charlie | Yes | No deliberate activity generated |

The purpose is to demonstrate that the connector can distinguish:

- Access that exists
- Access that has evidence of use
- Access for which no activity is currently observed

---

## 15. AWS Sources Prepared for the Connector

The AWS-side setup now provides four main evidence sources.

### IAM Authorization Configuration

Used to collect:

- Users
- Groups
- Roles
- Managed policies
- Inline policies
- Group membership
- Role trust relationships

Primary collection API:

`GetAccountAuthorizationDetails`

### IAM Last Accessed

Used to collect:

- Service usage
- Action-level usage where available
- Last accessed time
- Last accessed region
- Last accessed entity

### CloudTrail Event History

Used to collect:

- Recent management events
- Event name
- User/identity
- Event time
- Event source
- Resource information
- Detailed event information

### Access Analyzer

Used to collect:

- External access findings

For this test account, the current result is empty.

---

## 16. Current AWS Setup Summary

The AWS test environment for the `PROD` target account contains the following.

The setup intentionally contains:

- Multiple users
- Group-based permissions
- Direct user permissions
- Multiple roles
- Role chaining
- A broad administrative permission scenario
- A mismatched AssumeRole scenario
- Real role-assumption activity
- An inactive-user comparison
- Service-level usage data
- Action-level usage data
- CloudTrail management activity
- Access Analyzer with an empty external-access result
- A `$1` monthly budget alert

No production resources or application workloads were created as part of this setup.

The `DEV` target account (section 0) mirrors the collector-facing parts of this setup — an `AuditReadOnlyRole` with the same read-only permissions — without duplicating the full set of test-user scenarios above.
