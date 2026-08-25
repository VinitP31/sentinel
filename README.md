# Sentinel

Sentinel is a local, read-only AWS IAM security audit proof of concept. It collects IAM configuration and usage evidence across multiple AWS accounts, builds a relationship graph of who can access what, applies deterministic security rules, and uses an AI layer to explain the resulting findings in plain language through a Streamlit dashboard.

## What it does

- Discovers accounts in an AWS Organization and audits a configured set of target accounts (currently PROD and DEV).
- Assumes a read-only role in each target account — no long-lived credentials per account.
- Collects IAM configuration, usage evidence, and relationship data for each account independently.
- Normalizes AWS-specific data into a common model, then builds a relationship graph (who can assume what, who holds what policy).
- Applies deterministic security rules — the same input always produces the same findings.
- Uses an AI layer to explain each finding in plain language, grounded only in the evidence already collected.
- Combines per-account results into a single multi-account view.
- Never writes to AWS. No create, update, delete, attach, or detach calls of any kind.

## How it works

```
Management Account
        |
        v
AWS Organizations account discovery
        |
        v
Assume read-only role (per target account)
        |
        v
PROD / DEV
        |
        v
Per-account audit pipeline (IAM, usage evidence, graph, rules, AI)
        |
        v
Account-specific outputs
        |
        v
Combined findings / combined report
```

Each account is audited independently, through the same pipeline. One account failing does not stop the others.

## Current capabilities

- Multi-account orchestration across a configured Management Account and target accounts (PROD, DEV).
- Cross-account `AssumeRole` into a dedicated read-only audit role per account.
- AWS Organizations account discovery.
- IAM configuration collection, normalization, and group-inheritance resolution.
- IAM Last Accessed evidence collection (bounded concurrency, 5 workers).
- CloudTrail Event History collection (90-day management-event window).
- IAM Access Analyzer external-access findings.
- A relationship graph (identities, groups, roles, policies) with an interactive visualization.
- Deterministic security rules: broad permission, administrative access, indirect privilege path, potentially unused access.
- An AI layer that explains findings using only the evidence already collected (bounded concurrency, 5 workers).
- Account-scoped output plus a combined multi-account findings file and report.
- A Streamlit dashboard for running an audit and reviewing results.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in AWS_REGION and (optionally) OPENAI_API_KEY / OPENAI_MODEL for the AI explanation stage
```

Multi-account dashboard (the primary way to run Sentinel):

```bash
streamlit run app.py
```

Paste or retrieve temporary Management Account credentials in the browser UI, then click **Connect & Audit**.

Single-account CLI (audits whatever account the local AWS credential chain authenticates as):

```bash
python -m src.main
```

Outputs are written to `output/`, which is gitignored — raw evidence contains account IDs, principal names, and full policy documents, so it must never be committed.

## AWS setup

Sentinel needs:

- A Management Account identity with permission to list Organization accounts and assume a role in each target account.
- A dedicated read-only audit role in each target account, trusting the Management Account identity.
- The audit role restricted to read-only IAM, CloudTrail, and Access Analyzer permissions — no write access of any kind.

See `docs/AWS-SETUP-RECORD.md` for the exact accounts, roles, and test scenarios configured for this POC.

## Dashboard

- **Overview** — what is wrong with this environment, in plain language, in under a minute.
- **Findings** — the complete set of findings Sentinel detected, filterable by account and rule.
- **Accounts** — which accounts have problems, with per-account posture and top concerns.
- **Graph** — how identities, roles, and policies are connected, with a downloadable interactive graph.

## Output

- `output/<ACCOUNT>/` — one directory per audited account (e.g. `output/PROD/`, `output/DEV/`), containing that account's raw evidence, normalized data, relationship graph, findings, evidence package, AI explanations, and its own `REPORT.html`.
- `output/combined_findings.json` — every account's findings combined into one file, each entry tagged with its source account.
- `output/MULTI_ACCOUNT_REPORT.html` — a combined, executive-style report across all audited accounts.

## Findings

- **Broad permission** — a policy allows a wildcard action and resource (e.g. `Action: *`, `Resource: *`).
- **Administrative access** — a principal has administrator-level access.
- **Indirect privilege path** — a principal can reach administrative access indirectly, through a chain of role assumptions.
- **Potentially unused access** — configured access with no corresponding activity observed in the collected evidence. This does not prove the access is unnecessary — it means the access should be reviewed.

Every finding records how the access was obtained (direct, inline, or inherited through a group).

## Performance

A recent local run audited 2 accounts (PROD and DEV) with 22 total findings and 0 failures in approximately 1 minute 46 seconds. This is an observed result on this POC's test accounts, not a guaranteed runtime, an SLA, or a production benchmark.

## Testing

The test suite currently has 270 tests across 19 test files (`pytest -q`). All AWS and AI calls are mocked — the suite never makes a real AWS or OpenAI call.

## Limitations

- Models identity policies, inline policies, group inheritance, and role assumption only — not the full AWS authorization model (resource policies, permissions boundaries, session policies, and organization policies are out of scope).
- CloudTrail evidence is limited to Event History: 90 days, management events only, one region.
- IAM Last Accessed reflects access attempts (including denied ones), not only successful calls, and has its own propagation delay and historical-tracking limitations.
- The target account list (PROD/DEV) is fixed configuration, not automatic discovery-driven onboarding.
- Credential retrieval via the local AWS CLI and terminal credential printing are local-development conveniences only, not a production credential flow.
- The graph and AI explanations are advisory — they help interpret evidence, they do not replace a full AWS policy evaluation.

## Status

Sentinel is a proof of concept. It is not a production-ready security platform.
