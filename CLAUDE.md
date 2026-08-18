# CLAUDE.md

Instructions for working on this project. Read fully before writing code.

---

## What this is

A local proof of concept that reads **one** AWS account and identifies access that appears excessive.

It collects IAM configuration and usage evidence, normalizes both, builds a relationship graph, applies deterministic security rules, and passes the resulting findings to an AI layer that explains them.

**Read-only. This code must never write to AWS.** No create, update, delete, attach, detach, or put calls of any kind. If a task seems to require one, stop and ask.

The full design lives in `docs/POC.md`. This file is the working contract.

---

## Layer boundaries — do not cross these

```
src/aws/        knows AWS. Makes no security judgement.
src/normalize/  translates AWS vocabulary into the common model.
src/graph/      relationships and path-finding. Knows nothing about AWS.
src/analysis/   security rules. Operates only on the common model.
src/ai/         explains findings that already exist.
```

Two rules:

1. **No AWS-specific field name, ARN parsing, or boto3 import appears outside `src/aws/` and `src/normalize/`.** If `src/analysis/` needs to know something is an AWS role, the normalized record should already say so.
2. **Collection never decides whether something is a problem.** A collector returns data and a status. It does not filter, rank, or flag.

This separation is the point of the project — it is what lets a second provider be added later by writing one new collector. Violating it for convenience defeats the exercise.

---

## Non-negotiable modeling rules

These are correctness requirements, not preferences. Each one has been wrong in an earlier draft.

### There is no `HAS_ROLE` edge

A group holds policies. A group does **not** hold roles. No principal "has" a role.

Never emit `User -> HAS_ROLE -> Role` or `Group -> HAS_ROLE -> Role`. The relationship is `Principal -> CAN_ASSUME -> Role`.

### `CAN_ASSUME` requires both sides to agree

Create the edge only when **both** are true:

- a policy attached to the principal (directly, inline, or via group) allows `sts:AssumeRole` on the target role, **and**
- the target role's trust policy names that principal

An edge built from the grant alone describes a path that does not work. That produces a **false finding**, which is worse than a missed one — it destroys confidence in every other finding in the report.

There is a test case for this: `orphan-role` in the test account trusts `bob`, while `alice` holds a grant on it. No edge should appear for alice.

### Deny must survive normalization

AWS gives an explicit `Deny` precedence over any `Allow`, however many Allows exist. Every permission record carries its `effect`. Never drop, filter out, or ignore Deny statements.

The graph edge `Policy --CONTAINS--> Permission` is deliberately **effect-neutral**. `CONTAINS` does not mean "permits". Do not rename it to `ALLOWS`.

Test case: `auditor-policy` allows `iam:Get*` and separately denies `iam:GetCredentialReport`. If analysis reports carol as able to read the credential report, Deny is being ignored.

### Wildcards stay as written

Do **not** expand `s3:*` or `*` into the individual actions they cover. Expansion inflates the dataset and discards the fact that a broad grant was made — which is itself the finding. Do wildcard matching at analysis time.

### This is not an authorization engine

Effective AWS access can involve resource policies, permissions boundaries, session policies and organization policies. This POC models identity policies, inline policies, group inheritance and role assumption. **Nothing more.**

Do not attempt to implement full AWS policy evaluation. Where a limitation applies, state it in the output rather than working around it.

---

## AWS behaviours that will cost you time

### Pagination is mandatory

`get_account_authorization_details`, `get_service_last_accessed_details` and `lookup_events` all paginate. Use boto3 paginators where available.

Incomplete pagination produces silently incomplete data, which is worse than an error because it looks like a successful run. Terminate only on the absence of a token — never on an empty page.

### Policy documents may or may not be encoded

The AWS API contract says policy documents are URL-encoded. **Boto3 decodes and parses them automatically**, returning a dict.

Check the type before decoding. Never blindly URL-decode — you will corrupt an already-decoded document.

```python
doc = version["Document"]
if isinstance(doc, str):
    doc = json.loads(unquote(doc))
```

### Timestamps are not JSON-serializable

Boto3 returns `datetime` objects. `json.dump` raises on them. Use `src/util/io.py::write_json`, which handles this. Do not call `json.dump` directly.

### Last-accessed data lags about four hours

Recent activity does not appear immediately. An empty result shortly after generating test activity is expected, not a bug. Do not add retry logic to work around it.

Also: it reports **attempts**, including denied ones — not successful calls. And it applies only identity-policy logic, so it can overstate what a principal can reach.

### CloudTrail Event History is narrower than it looks

90 days, management events only, one Region. Data events such as `s3:GetObject` never appear.

Every finding derived from it must be phrased as scoped to the evidence, not absolute. See the wording rule below.

---

## Findings

### Deterministic, always

Findings come from code, never from a model. A finding must give the same answer on every run and it must be possible to state exactly why an item was flagged. AI does not decide whether something is a problem.

### Wording

Always:

> No corresponding activity observed in the collected evidence.

Never:

> This permission has never been used.

The evidence window is bounded, data events are not collected, and legitimately infrequent operations fall outside any window. Every finding carries the evidence window it was derived from.

Name the rule `potentially_unused_access`, not `unused_access`.

### Attribution

Every finding must record **how** the access was acquired — directly attached, inline, or inherited from a named group. "bob has administrative access" is not actionable. "bob has administrative access via the developers group" is.

---

## AI layer

Receives a structured evidence package. Never has AWS access.

**Does:** explain findings, correlate related evidence, explain graph paths, prioritize, summarize, suggest least-privilege alternatives.

**Does not:** invent permissions, identities, events or relationships; treat missing evidence as proof of absence; act as an authority on AWS configuration.

The evidence package **must** include an `evidence_limitations` field. The model cannot qualify a conclusion if the constraints are absent from its input. This field is required, not optional.

---

## Build order

Build one stage at a time. Each produces a file to open and inspect before moving on. Do not scaffold stubs for later stages.

| # | Stage | Status | Verify by |
|---|---|---|---|
| 1 | Authentication | done | Correct account ID returned |
| 2 | IAM collection + raw save | done | Open `output/raw/`, read it |
| 3 | Normalize direct + inline policies | todo | Counts reconcile against raw |
| 4 | Normalize group inheritance | todo | Inherited records name their source group |
| 5 | Last-accessed collection | todo | Dates for alice, absent for bob |
| 6 | Deterministic rules | todo | Output matches planted test cases |
| 7 | Graph + path finding | todo | Chain found; orphan edge rejected |
| 8 | CloudTrail collection | todo | Events attributed to the right principal |
| 9 | Evidence package | todo | Includes limitations |
| 10 | AI layer | todo | Grounded in supplied evidence only |

Update the Status column as stages complete.

---

## Test account — expected results

Region: `us-east-1`. Connector runs as `poc-aws-audit-collector` with the
customer-managed policy `POC-AWS-IAM-Audit-ReadOnly`.

Findings must match the table below. These conditions were planted
deliberately, so the correct answer is known in advance.

| Entity | Configuration | Expected finding |
|---|---|---|
| `alice` | `Developers` group -> `POC-Developer-S3-ReadOnly`; direct `POC-UntrustedRole-Assume`; real STS **and** S3 activity | Active. Neither dormancy nor unused-S3 should fire |
| `bob` | `Auditors` group -> `POC-Developer-S3-ReadOnly` (identical to alice's) plus `POC-Auditor-IAM-Deny-Test`; no activity | Potentially unused S3 access; dormant identity |
| `Auditors` group | `POC-Auditor-IAM-Deny-Test`: Allow `iam:List*`/`iam:Get*` **and** Deny `iam:GetCredentialReport` | Members must **not** be reported as able to read the credential report |
| `charlie` | `POC-Developer-S3-ReadOnly` attached **directly**, not via a group; no activity | Same findings as bob, with attachment recorded as direct rather than inherited |
| `DeveloperRole` | Trusts `alice`. Holds `POC-Developer-Admin-Assume` | `CAN_ASSUME` edge from alice |
| `AdminRole` | Trusts `DeveloperRole`. Holds `POC-Admin-Access` | Broad access. Indirect privilege path: alice -> DeveloperRole -> AdminRole |
| `UntrustedRole` | Trusts `bob`. Alice holds a grant on it | **No** `CAN_ASSUME` edge for alice |
| Access Analyzer | `POC-External-Access`, external type, ACTIVE | Empty findings. Must be handled as a valid result, not a failure |

### Notes on this account

**Broad access is reachable only through the chain.** No user holds
administrative permissions directly — `POC-Admin-Access` sits on `AdminRole`,
two hops from alice. The broad-access and escalation findings therefore depend
on `CAN_ASSUME` working correctly. If the graph is wrong, they will not appear
at all rather than appearing wrongly.

**Charlie exists to separate direct from inherited attachment.** Alice, bob and
charlie hold the same policy by three different routes. Findings must record
which route, because "charlie has S3 access" and "charlie has S3 access via a
directly attached policy" have different remediations.

**`UntrustedRole` is the negative test.** Alice holds a policy allowing
`sts:AssumeRole` on it, but the trust policy names only bob. The assume genuinely
fails when attempted. If an edge appears for alice, the code is reading the grant
without checking the trust policy.

**Alice has both STS and S3 activity.** Her `AssumeRole` call against
`DeveloperRole` and a `ListBuckets` call both appear in CloudTrail Event History.
Bob and charlie hold the identical S3 policy with no activity. That contrast is
the core demonstration: same permission, different usage evidence, different
finding.

**The two usage sources disagree on alice's S3 access.** CloudTrail shows the
`ListBuckets` call; IAM last-accessed did not report authenticated S3 usage for
her at the time of checking. Treat CloudTrail as authoritative here, consistent
with AWS's own guidance.

Do not write code that reconciles the two sources by preferring whichever is
non-empty, and do not add retries to make last-accessed agree. Report what each
source says, and let the finding cite which source supports it. A disagreement
between sources is information, not an error to be smoothed over.

**Alice has no active access key.** It was deleted after the role-assumption
test. Generating further activity as alice requires issuing a new one.

## Conventions

- Python 3.11+, standard library plus the four packages in `requirements.txt`
- No new dependency without asking
- Type hints on function signatures; docstrings only where the reason isn't obvious from the code
- Small modules, plain functions. No classes unless there is genuine state to hold
- No frameworks, no dependency injection, no plugin registries. This is a POC
- Every collector returns `(data, status)` so a partial run stays distinguishable from a complete one
- Config comes from `src/config.py`, which reads `.env`. No hard-coded account IDs, ARNs, regions or paths anywhere else

---

## Never do these

- Write to AWS in any way
- Commit anything under `output/` — it contains account IDs, principal names and full policy documents
- Commit `.env` or any credential
- Print or log credentials, secrets, or session tokens
- Enable the Access Analyzer **unused-access** analyzer — it is charged per principal per month. External access only
- Create a CloudTrail trail, S3 bucket, CloudWatch log group, or any compute resource
- Add a database. JSON files are the storage decision
- Silently return empty data when a call failed. A failure and an empty result are different states
- Add retry loops to defeat the last-accessed propagation delay
- Use an AWS managed policy for the connector's own permissions. The explicit list is deliberate

---

## When something is ambiguous

Ask rather than guessing, particularly on:

- anything that would cross a layer boundary
- anything that would require a write call
- whether a finding should be a candidate or an assertion
- adding a dependency

Getting the modeling rules above wrong produces confident, plausible, wrong findings. That is the failure mode this project most needs to avoid.
