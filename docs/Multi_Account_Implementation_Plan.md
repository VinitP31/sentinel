# Multi-Account Audit Implementation

This document describes how Sentinel's multi-account auditing works. The implementation is complete and in use — this is current-state engineering documentation, not a plan for future work.

## Problem being solved

The original connector audited exactly one AWS account, authenticated as whatever identity the local AWS credential chain provided. A single security review usually spans more than one account (for example, a production account and a development account). Multi-account support adds:

- Discovery of accounts in an AWS Organization, for confirmation.
- A read-only role assumed in each target account, instead of one long-lived credential per account.
- The existing single-account audit pipeline run once per account, unmodified.
- One combined result across all audited accounts.

## Architecture

```
src/aws/          auth.py (get_session, verify_identity, assume_role),
                  organizations_collector.py, iam_collector.py,
                  last_accessed_collector.py, cloudtrail_collector.py,
                  access_analyzer_collector.py
src/normalize/    iam.py — raw AWS shapes -> common model
src/graph/        build.py, visualize.py
src/analysis/     rules.py, indirect_privilege_path.py
src/evidence/     build.py
src/ai/           explain.py
src/report/       build.py (per-account report), multi_account.py (combined report)
src/util/         io.py, status.py
src/config.py     .env-sourced constants, account-scoped output-path functions
src/main.py       run_pipeline() (the per-account pipeline) + run() (single-account CLI)
src/orchestrator.py   multi-account orchestration (new)
app.py            Streamlit dashboard — the primary way to run a multi-account audit
```

`src/main.py::run_pipeline(session, identity, output_dir, progress_callback=None)` is the single-account audit pipeline, unchanged in behavior from the original single-account implementation. `src/main.py::run()` is the single-account CLI entry point (`python -m src.main`) — it prompts for a profile/region/expected account ID, builds one session, and calls `run_pipeline` once. `src/orchestrator.py` and `app.py` call `run_pipeline` once per target account instead.

## Authentication flow

`src/aws/auth.py` provides:

- `get_session(profile_name, region_name)` — builds a `boto3.Session` from a local named profile. Used by the single-account CLI path.
- `verify_identity(session, expected_account_id=None)` — calls `sts:GetCallerIdentity`, optionally asserting the authenticated account matches an expected ID. Used by both the single-account and multi-account paths, including once per account after assuming a role, to confirm the session landed in the expected account before any audit work begins.
- `assume_role(base_session, role_arn, session_name="sentinel-audit", duration_seconds=3600)` — exchanges a base session's identity for temporary credentials scoped to `role_arn`, returning a new `boto3.Session`. Raises `AuthError` (never a raw `ClientError`) on failure, matching `verify_identity`'s existing exception convention.

In the Streamlit UI, the base Management Account session is built from pasted or locally-retrieved temporary credentials (`app.py::build_session`) rather than a named profile — `assume_role` and everything downstream treats it identically either way, since every collector and `run_pipeline` only ever receives a plain `boto3.Session`.

## Organizations account discovery

`src/aws/organizations_collector.py::collect(session)` calls `organizations:ListAccounts` (paginated) from the Management Account session and returns every account the identity can see, with no filtering or judgment — filtering to the configured target accounts is the orchestrator's job, not the collector's. A standalone (non-Organizations) account is a distinct, valid outcome (`AWSOrganizationsNotInUseException`), reported as its own `CollectionStatus`, not folded into a generic failure.

## AssumeRole

`src/orchestrator.py` assumes `arn:aws:iam::<account_id>:role/AuditReadOnlyRole` in each configured target account:

```python
TARGET_ACCOUNTS = {
    "PROD": "328865868092",
    "DEV": "587762853586",
}
ROLE_NAME = "AuditReadOnlyRole"
```

The target account list is fixed configuration, not derived from Organizations discovery — discovery confirms/logs what exists in the org, it does not decide which accounts get audited.

## Per-account sessions

`audit_account(base_session, label, account_id, progress_callback=None)` assumes the role, verifies identity, then calls `run_pipeline` with that account's own temporary session. Each account's session is independent — PROD's temporary credentials are never reused for DEV, and are discarded once that account's audit finishes.

## Per-account audit pipeline

`run_pipeline` is the same 9-stage pipeline previously run only for a single account, now called once per target account, completely unmodified:

1. IAM Configuration Collection
2. IAM Normalization
3. Group Inheritance
4. Last Accessed Evidence
5. Relationship Graph
6. CloudTrail Event History
7. Deterministic Security Analysis
8. Access Analyzer & Evidence Package
9. AI Security Explanation

(Stage numbering in the code reflects historical build order — CloudTrail collection and the relationship graph run before deterministic analysis, since analysis depends on both.) A `progress_callback`, when supplied, is notified at the start/completion/failure of every stage, with duration — this is what drives the Streamlit UI's live progress display.

## Account-scoped outputs

`src/config.py` provides account-scoped path functions (`raw_dir`, `normalized_dir`, `graph_dir`, `findings_dir`, `evidence_dir`, `ai_dir`, `report_path`), each taking an optional `account_label`. With no label, every function resolves to the original single-account constants (`OUTPUT_DIR`, `RAW_DIR`, etc.) — the single-account CLI path (`python -m src.main`) is unaffected and still writes to `output/raw/`, `output/findings/findings.json`, `output/REPORT.html`. With a label (e.g. `"PROD"`), output is rooted under `output/<label>/` instead, so accounts never collide.

## Combined findings

`audit_all_accounts(base_session, progress_callback=None)` runs Organizations discovery, then `audit_account` for each target account, then reads each successful account's own unmodified `findings.json` and builds a second, in-memory, tagged copy — each finding annotated with `account_id`/`account_name` on top of its existing fields, without mutating the per-account file on disk. The combined result is written to `output/combined_findings.json`:

```json
{
  "management_account_id": "...",
  "organizations_status": {...},
  "accounts": [{"account_label": "PROD", "account_id": "...", "status": "success", "finding_count": N}, ...],
  "accounts_succeeded": 2,
  "accounts_failed": 0,
  "findings": [{"account_id": "...", "account_name": "PROD", "principal": {...}, "rule": "...", ...}, ...],
  "total_findings": N
}
```

## Combined report

`src/report/multi_account.py::render_multi_account_report` reads `combined_findings.json` and writes `output/MULTI_ACCOUNT_REPORT.html` — an executive-style page with account cards, a curated set of key security risks, drill-down links to each account's own `REPORT.html`, and the complete tagged findings list. It never recomputes findings and never embeds a graph (each account's own `REPORT.html` has its own). The Streamlit dashboard (`app.py`) reads the same `combined_findings.json` aggregate to render its Overview/Findings/Accounts/Graph tabs directly, rather than parsing the HTML report.

## Failure handling

One account's failure never aborts another account's audit. `audit_account` catches authentication failures (bad role ARN, denied assume-role) and pipeline failures separately, returning a result record — `{"status": "failed", "failure_stage": "authentication" | "collection", "error": ...}` — instead of raising. `audit_all_accounts` aggregates whatever succeeded; `accounts_succeeded`/`accounts_failed` reflect the actual outcome per account.

## Test coverage

Multi-account-specific behavior is covered by `tests/test_auth.py` (`assume_role`), `tests/test_organizations_collector.py`, and `tests/test_orchestrator.py` (per-account success/failure isolation, aggregate counts, findings tagging). No AWS credentials or network calls are used — every test mocks the relevant boto3 client. The full suite currently has 270 tests across 19 files; run with `pytest -q`.

## Current limitations

- The target account list (PROD/DEV) is fixed configuration, not automatic onboarding driven by Organizations discovery.
- Accounts are audited sequentially, one after another — there is no cross-account concurrency (bounded concurrency exists within a single account's Last Accessed Evidence and AI Explanation stages only).
- The combined report and combined findings file do not perform any cross-account security correlation — each finding is exactly what that account's own deterministic rules produced, only tagged with its source account.
- Temporary credentials for the Management Account, in the local Streamlit UI, are obtained via pasted values or the local AWS CLI — this is a local-development convenience, not a production credential-issuance mechanism.
