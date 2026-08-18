# AWS IAM Security Audit Connector POC

## 1. Purpose

This document describes the AWS proof of concept being built to demonstrate how an IAM security connector can collect AWS access data, represent relationships between identities and permissions, identify security issues, and use AI to explain findings.

The goal is demonstration, not production implementation.

The POC is intentionally limited to one AWS account and focuses on the core connector pattern that can later be reused for other sources such as Azure, VMware, Okta, and similar systems.

---

## 2. What We Are Building

```
AWS Test Account
       |
       v
Python + Boto3 Connector
       |
       +--> IAM Configuration
       +--> IAM Last Accessed
       +--> CloudTrail
       +--> Access Analyzer
       |
       v
Normalize Data
       |
       v
Build Relationship Graph
       |
       v
Security Checks
       |
       v
Evidence + Findings
       |
       v
AI Analysis
       |
       v
Security Explanation / Recommendations

```

The connector is read-oriented. It collects information from AWS and does not perform remediation.

---

## 3. Why We Are Building It

An IAM audit needs more than a list of users and policies.

We want to demonstrate that the system can understand:

- who has access
- what permissions they have
- through which policy, group, or role
- which roles a principal can assume
- what activity has been observed
- how identities, permissions, roles, and resources are connected

Combining these allows the POC to identify useful security candidates such as broad access, indirect privilege paths, and potentially unused access.

---

## 4. POC Scope

### Included

One AWS account. IAM users, groups, roles, and policies. Role trust policies. IAM Service/Action Last Accessed information. CloudTrail management events. IAM Access Analyzer external-access findings. Raw JSON evidence. Normalized JSON data. Relationship graph. Deterministic security checks. AI-generated explanation and recommendations.

### Not Included

Multiple AWS accounts. AWS Organizations. Production customer onboarding. Cross-account AssumeRole. Real-time event processing. EventBridge. Database. Continuous synchronization. Deleted/stale record handling. CloudTrail data events. CloudTrail Lake. Paid IAM Access Analyzer unused-access analysis. Automated remediation. VMware. Azure / Microsoft Entra ID. Production graph database. Autonomous agents.

---

## 5. End-to-End Flow

```
                          AWS TEST ACCOUNT
                                 |
     +-------------+-------------+-------------+-------------+
     |             |                           |             |
     v             v                           v             v
    IAM      IAM Last Accessed           CloudTrail    Access Analyzer
Configuration   Information          Management Events  External Access
     |             |                           |             |
     +-------------+-------------+-------------+-------------+
                                 |
                                 v
                     Python / Boto3 Connector
                                 |
                                 v
                          Raw AWS JSON
                                 |
                                 v
                           Normalization
                                 |
                                 v
                        Relationship Graph
                                 |
                                 v
                       Deterministic Checks
                                 |
                                 v
                         Evidence Package
                                 |
                                 v
                             AI Layer
                                 |
                                 v
                   Findings / Recommendations

```

The four AWS sources are independent evidence sources. The connector calls each source directly — Access Analyzer consumes nothing from the other three, and the pipeline is complete without it.

---

## 6. Authentication

### Current POC

The POC uses credentials for the controlled AWS test account.

Python uses the normal AWS credential chain.

Before collecting data, the connector calls `STS GetCallerIdentity` to verify the account it is connected to.

```
Python
  |
  v
AWS Credentials
  |
  v
GetCallerIdentity
  |
  v
Verify Account
  |
  v
Start Collection

```

### Production Difference

Cross-account AssumeRole is not part of this POC.

The eventual production pattern would be:

```
Auditing Account
    |
    | STS AssumeRole
    v
Customer AWS Account
    |
    v
Read-only Audit Role

```

The POC therefore demonstrates the connector logic without implementing customer onboarding or cross-account access.

---

## 7. AWS Data Sources

### IAM

**Purpose:** find what access is configured.

**Provides:** users, groups, roles, policies, policy relationships, role trust policies.

**Primary API:** `GetAccountAuthorizationDetails`

This is the main IAM configuration snapshot used by the POC. It is paginated.

### IAM Last Accessed

**Purpose:** understand longer-term service/action access attempts.

```
GenerateServiceLastAccessedDetails
             |
             v
           Job ID
             |
             v
GetServiceLastAccessedDetails
             |
             v
Service / Action Last Accessed

```

Recent activity is asynchronous and may take several hours to appear. After generating test activity, allow the documented AWS propagation period before treating an empty result as meaningful.

IAM Last Accessed represents access **attempts**, including denied attempts, and does not report unauthenticated requests.

Action-level tracking also has service-specific historical start dates, so absence of an action-level result does not automatically mean the action was never used.

### CloudTrail

**Purpose:** obtain detailed recent AWS management activity.

The POC uses:

```
CloudTrail Event History
        |
        v
LookupEvents

```

Event History provides the previous 90 days of management events for the selected Region.

Examples:

```
CreateRole
AttachRolePolicy
PutRolePolicy
CreatePolicy
AssumeRole
ListRoles
GetRole

```

The POC does not treat CloudTrail Event History as a record of all AWS activity. For example, `s3:GetObject` is a data event and is outside the management-event scope being used here.

CloudTrail results can also be paginated.

### Why both activity sources

The two are complementary rather than interchangeable. IAM Last Accessed gives the long-range signal across a wider tracking period; CloudTrail gives concrete, attributable detail on individual calls. AWS itself directs users to CloudTrail as the authoritative source for whether API calls succeeded or were denied access, which is why both are collected rather than relying on Last Accessed alone.

### IAM Access Analyzer

**Purpose:** identify supported external-access exposure.

```
AWS Resource
     |
     v
Resource Policy
     |
     v
External Principal
     |
     v
Access Analyzer Finding

```

For this POC, the focus is external-access analysis.

If the test account contains no supported public or cross-account access, an empty result is expected and is not a failure.

Access Analyzer external-access analysis is regional.

Paid unused-access analysis is intentionally excluded.

---

## 8. IAM Data We Collect

### Users

Name, ID, ARN, creation date, group membership, policy relationships.

### Groups

Name, ID, ARN, creation date, members, attached policies.

A group contains users and can have policies attached to it. **A group does not contain or "hold" roles.**

### Roles

Name, ID, ARN, creation date, trust policy, attached policies, inline policies.

### Policies

Name, ARN, ID, type, policy document, attachments.

The original policy document is retained as evidence.

---

## 9. Role Assumption

Role assumption is important because access can be indirect.

The graph must **not** model:

```
User  -> HAS_ROLE -> Role
Group -> HAS_ROLE -> Role

```

Instead:

```
Principal -> CAN_ASSUME -> Role

```

For the standard role-assumption scenario:

```
Principal's applicable policy
        |
        | allows sts:AssumeRole
        v
Target Role
        |
        | trust policy permits principal
        v
CAN_ASSUME relationship

```

Example:

```
Alice
  |
  +--> CAN_ASSUME --> DeveloperRole

```

Indirect path:

```
Alice
  |
  +--> CAN_ASSUME --> DeveloperRole
                           |
                           +--> CAN_ASSUME --> AdminRole
                                                  |
                                                  +--> AdministratorAccess

```

This is one of the main reasons for building a graph rather than only displaying a flat permissions list.

---

## 10. Policy Representation

A policy statement can contain:

```
Effect
Action
Resource
Condition
Principal, where applicable

```

The POC preserves both `Allow` and `Deny`. An explicit Deny must not be removed during normalization.

Wildcards are also preserved. For example:

```
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

```

should remain represented as a wildcard.

The POC does not expand `*` into every individual AWS action, because the wildcard itself is important security evidence.

---

## 11. Normalization

AWS APIs already return structured data, usually represented through JSON-compatible structures.

Normalization means converting AWS-specific fields into a consistent internal structure.

Example AWS object:

```
{
  "RoleName": "DeveloperRole",
  "Arn": "arn:aws:iam::123456789012:role/DeveloperRole",
  "CreateDate": "2026-08-17T10:00:00Z"
}

```

Normalized representation:

```
{
  "provider": "aws",
  "type": "role",
  "id": "arn:aws:iam::123456789012:role/DeveloperRole",
  "name": "DeveloperRole",
  "created_at": "2026-08-17T10:00:00Z"
}

```

The purpose is to make downstream graph and analysis logic independent of AWS-specific field names.

---

## 12. Common Data Model

The POC needs a small internal model:

```
Identity
Group
Role
Policy
Permission
Resource
Activity
LastAccess
Relationship

```

Example identity:

```
{
  "id": "...",
  "provider": "aws",
  "type": "user",
  "name": "Alice",
  "arn": "..."
}

```

Example permission:

```
{
  "policy_id": "...",
  "effect": "Allow",
  "actions": ["s3:GetObject"],
  "resources": ["arn:aws:s3:::example-bucket/*"]
}

```

Example relationship:

```
{
  "source": "...",
  "target": "...",
  "relationship": "CAN_ASSUME"
}

```

Normalized objects should retain a reference to the original raw evidence.

---

## 13. Relationship Graph

The graph represents how access is connected.

### Nodes

```
AWS Account
User
Group
Role
Policy
Permission
Resource

```

### Relationships

```
User                        --MEMBER_OF-->    Group
User / applicable identity  --HAS_POLICY-->   Policy
Group                       --HAS_POLICY-->   Policy
Role                        --HAS_POLICY-->   Policy
Principal                   --CAN_ASSUME-->   Role
Policy                      --CONTAINS--->    Permission
Permission                  --TARGETS---->    Resource

```

The Permission node carries the policy effect — `effect = Allow` or `effect = Deny`. Therefore `CONTAINS` does not imply that the permission is allowed.

### Example

```
Alice
  |
  +--> MEMBER_OF --> Developers
                           |
                           +--> HAS_POLICY --> DeveloperPolicy
                                                    |
                                                    +--> CONTAINS
                                                           |
                                                           v
                                                    s3:GetObject
                                                           |
                                                           +--> TARGETS
                                                                   |
                                                                   v
                                                              S3 Resource

```

---

## 14. Graph Technology

For the POC, **NetworkX** is sufficient.

It allows the connector to create a local graph and traverse relationships without introducing a graph database.

A simple visualization can use NetworkX with PyVis.

The important part is demonstrating the graph model and access relationships, not selecting a production graph database.

---

## 15. Security Analysis

Security checks should be deterministic first.

### Broad permission

```
Effect = Allow
Action = *
Resource = *

```

### Administrative access

```
Principal
    |
    +--> HAS_POLICY
            |
            v
    AdministratorAccess

```

### Indirect privilege path

```
Principal
    |
    +--> CAN_ASSUME --> RoleA
                            |
                            +--> CAN_ASSUME --> RoleB
                                                   |
                                                   +--> AdministratorAccess

```

### Explicit Deny precedence

The analysis must preserve explicit Deny statements.

For example:

```text
Allow iam:Get*
+
Deny iam:GetCredentialReport
=
GetCredentialReport remains denied
```

An explicit Deny must not be treated as ordinary positive access simply because an Allow also matches.

### Potentially unused access

Compare configured access with:

```
IAM Last Accessed
+
CloudTrail Activity

```

The finding should be phrased as:

> No corresponding activity observed in the collected evidence

rather than:

> This permission has never been used

because absence of observed activity is not proof that access is permanently unnecessary.

---

## 16. AI Layer

AI comes after the connector and deterministic analysis.

```
AWS Data
   |
   v
Normalize
   |
   v
Graph + Security Checks
   |
   v
Evidence Package
   |
   v
AI

```

### AI should

- explain findings
- correlate related evidence
- explain graph/access paths
- prioritize findings
- summarize evidence
- suggest remediation

### AI should not

- invent permissions
- invent activity
- invent users or roles
- invent graph relationships
- treat missing evidence as proof of absence

The AI is an interpretation layer over evidence collected by the connector.

---

## 17. Evidence Package

The connector provides the AI with focused evidence.

```
{
  "principal": {
    "name": "Bob",
    "type": "user"
  },
  "configured_access": [
    {
      "role": "AdminRole",
      "policy": "POC-Admin-Access",
      "actions": ["*"],
      "resources": ["*"]
    }
  ],
  "relationships": [
    {
      "from": "Alice",
      "relationship": "CAN_ASSUME",
      "to": "DeveloperRole"
    },
    {
      "from": "DeveloperRole",
      "relationship": "CAN_ASSUME",
      "to": "AdminRole"
    }
  ],
  "observed_activity": {
    "evidence_window_days": 90,
    "events": [
      {
        "event_name": "ListRoles",
        "timestamp": "..."
      }
    ]
  },
  "last_accessed": [
    {
      "service": "Amazon S3",
      "last_attempt": "..."
    }
  ],
  "analyzer_findings": [],
  "evidence_limitations": [
    "CloudTrail evidence covers management events only",
    "CloudTrail Event History covers the available 90-day window",
    "IAM Last Accessed represents access attempts",
    "The POC does not evaluate every AWS policy mechanism"
  ]
}

```

Including limitations lets the AI qualify conclusions correctly.

---

## 18. Raw Data and Traceability

The POC keeps raw AWS responses in addition to normalized data.

```
AWS API Response
       |
       +------------------+
       |                  |
       v                  v
    Raw Data          Normalize
                          |
                          v
                    Common Model
                          |
                          v
                       Graph
                          |
                          v
                      Finding

```

This allows a finding to be traced back to the original AWS evidence.

---

## 19. Implementation Considerations

Only connector-specific considerations that directly affect this POC are included.

### Pagination

AWS APIs can return multiple pages. The connector must handle pagination for APIs such as:

```
GetAccountAuthorizationDetails
GetServiceLastAccessedDetails
LookupEvents

```

### Policy Documents

IAM policy documents may be URL-encoded. The connector should inspect the returned value before decoding and avoid double-decoding an already decoded document.

### Timestamps

Boto3 can return timestamps as Python `datetime` objects. Before writing JSON, convert them to a JSON-safe representation such as ISO 8601.

### Collection Failures

The connector should not silently treat failed collection as empty data.

For example:

```
IAM               SUCCESS
CloudTrail        SUCCESS
Last Accessed     SUCCESS
Access Analyzer   FAILED

```

must remain distinguishable from:

```
Access Analyzer   SUCCESS
Findings          EMPTY

```

---

## 20. Tools

| Tool Purpose           |                                              |
| ---------------------- | -------------------------------------------- |
| Python                 | Connector implementation and data processing |
| Boto3                  | AWS API access                               |
| IAM                    | Access configuration                         |
| STS                    | Account identity verification                |
| IAM Last Accessed APIs | Usage evidence                               |
| CloudTrail             | Recent management activity                   |
| IAM Access Analyzer    | External-access evidence                     |
| JSON                   | Raw and normalized data                      |
| NetworkX               | Graph construction                           |
| PyVis                  | Graph visualization                          |
| AI model / API         | Explanation and recommendations              |

The POC does not require AWS compute infrastructure.

---

## 21. Cost and Security Constraints

The POC is designed to remain lightweight and avoid unnecessary AWS services.

Use:

```
Local machine
    |
    +--> Python
    +--> Boto3
    +--> JSON
    +--> NetworkX
    +--> PyVis
    +--> AI model/API

```

Avoid introducing:

```
EC2
RDS
Lambda
S3
CloudTrail trails with S3 storage
CloudTrail Lake
CloudTrail data events
CloudTrail Insights
CloudWatch Logs
Paid Access Analyzer unused-access analysis

```

CloudTrail Event History is used instead of configuring a long-term CloudTrail pipeline.

A low-threshold AWS budget alert should be configured before experimentation. A budget alert is an alert, not a hard spending limit.

Credentials must not be hard-coded or committed to source control.

---

## 22. Demonstration Scenarios

The test account should contain a few deliberately constructed scenarios so the POC visibly demonstrates the pipeline.

### Scenario 1: Normal access

```
Alice
  |
  +--> Developers
          |
          +--> DeveloperPolicy
                  |
                  +--> limited permissions

```

Demonstrates:

```
Identity -> Group -> Policy -> Permission

```

### Scenario 2: Broad access

```
Alice
  |
    +--> CAN_ASSUME --> DeveloperRole
                           |
                             +--> CAN_ASSUME --> AdminRole
                                                    |
                                                      +--> broad administrative permissions
```

Expected demonstration: broad administrative access is reachable indirectly through the role chain.

The broad administrative permission is on `AdminRole`, not directly on Bob.

### Scenario 3: Used vs potentially unused access

Create principals with comparable S3 permissions:

```
Alice   -> S3 permission + S3 activity observed
Bob     -> same S3 permission + no S3 activity observed
Charlie -> same S3 permission + no S3 activity observed
```

For the POC, Alice performed:

```text
aws s3 ls
```

which generated a successful CloudTrail `ListBuckets` management event.

IAM Last Accessed did not show authenticated S3 usage for Alice, so CloudTrail is the concrete evidence for this S3 activity. This also demonstrates that different AWS evidence sources can have different coverage and timing.

Expected demonstration:

```
Alice   -> S3 activity observed in CloudTrail
Bob     -> no corresponding S3 activity observed
Charlie -> no corresponding S3 activity observed
```

This demonstrates that the analysis compares configured access with observed activity rather than flagging every permission identically.

### Scenario 4: Indirect role access

```
Alice
  |
  +--> CAN_ASSUME --> DeveloperRole
                           |
                           +--> CAN_ASSUME --> AdminRole
                                                  |
                                                  +--> AdministratorAccess

```

Expected demonstration: indirect administrative access path detected.

### Scenario 5: Invalid role-assumption path

Configure a principal policy allowing `sts:AssumeRole` on `UntrustedRole`, but make the role trust a different principal.

The POC uses:

```
Alice
  |
    +--> policy allows sts:AssumeRole --> UntrustedRole

UntrustedRole
  |
    +--> trust policy allows Bob
```

Expected: **no** **`CAN_ASSUME`** **edge from Alice to UntrustedRole.**

This demonstrates that the graph does not create a role edge merely because `sts:AssumeRole` appears in a policy. The principal permission and the target role's trust policy both need to support the assumption.

## 23. Deny Precedence Test

The `Auditors` group has a dedicated policy:

`POC-Auditor-IAM-Deny-Test`

It contains both an IAM read Allow and an explicit Deny:

```text
Auditors
  |
    +--> Allow iam:List* / iam:Get*
    |
    +--> Deny iam:GetCredentialReport
```

This creates a real Allow-versus-Deny test case.

The POC must preserve both statements and treat the explicit Deny as taking precedence over the matching Allow.

This scenario is intentionally included so that code which only collects Allow statements does not pass the complete test set.

---

## 24. Test Timing

The test sequence should account for the different evidence sources:

```
Create / configure IAM test data
        |
        v
Perform controlled management activity
        |
        v
Wait for CloudTrail activity to become available
        |
        v
Allow IAM Last Accessed propagation period
        |
        v
Run connector
        |
        v
Compare configuration + activity

```

CloudTrail Event History and IAM Last Accessed have different availability characteristics. An immediately empty Last Accessed result should not be treated as a connector failure.

---

## 24. Current Limitations

The POC intentionally has several limitations:

- One AWS account only.
- CloudTrail evidence is limited to the available Event History management events.
- CloudTrail Event History provides a 90-day management-event window.
- IAM Last Accessed represents access attempts rather than only successful calls.
- IAM Last Accessed does not report unauthenticated requests.
- IAM Last Accessed has service/action historical tracking limitations.
- The POC does not implement the complete AWS authorization evaluation model.
- Resource-based policies are only partially represented.
- Permissions boundaries, session policies, and organization-level policies are outside the intended analysis scope.
- Access Analyzer is limited to the selected external-access capability.
- The graph is local.
- AI output is advisory and must remain grounded in collected evidence.

These limitations are acceptable because the purpose is to demonstrate the core connector pattern, not to reproduce the complete AWS authorization engine.

---

## 25. What This POC Demonstrates

The POC should demonstrate one complete vertical slice:

```
AWS Account
    |
    v
Collect AWS identity/access data
    |
    v
Collect usage evidence
    |
    v
Normalize
    |
    v
Build access graph
    |
    v
Identify security candidates
    |
    v
Prepare evidence
    |
    v
AI explains findings

```

The main architectural idea is:

```
Provider-specific Connector
          |
          v
      Common Model
          |
          v
     Graph + Analysis
          |
          v
          AI

```

AWS is the first implementation of this pattern.

The purpose is to demonstrate that a provider-specific connector can turn an external identity/access system into a common security representation that shared analysis and AI components can consume.

---

## 26. References

- AWS IAM authorization details — https\://docs.aws.amazon.com/IAM/latest/APIReference/API\_GetAccountAuthorizationDetails.html
- IAM last-accessed information — https\://docs.aws.amazon.com/IAM/latest/UserGuide/access\_policies\_last-accessed.html
- Generate service last-accessed details — https\://docs.aws.amazon.com/IAM/latest/APIReference/API\_GenerateServiceLastAccessedDetails.html
- Get service last-accessed details — https\://docs.aws.amazon.com/IAM/latest/APIReference/API\_GetServiceLastAccessedDetails.html
- CloudTrail Event History — https\://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
- CloudTrail LookupEvents — https\://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API\_LookupEvents.html
- IAM Access Analyzer — https\://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html
- IAM Access Analyzer external access — https\://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-create-external.html
- Boto3 — https\://boto3.amazonaws.com/v1/documentation/api/latest/
- NetworkX — https\://networkx.org/documentation/stable/