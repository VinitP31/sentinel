# Sentinel

An AWS IAM security audit connector — POC.

Reads one AWS account, normalizes IAM configuration and usage evidence, builds
a relationship graph, applies deterministic security rules, and has an AI
layer explain the resulting findings. Read-only, runs locally, writes JSON.

Design: `docs/POC.md`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# fill in AWS_PROFILE_NAME, AWS_REGION, EXPECTED_ACCOUNT_ID, and (optionally)
# OPENAI_API_KEY / OPENAI_MODEL for the AI explanation stage
```

`EXPECTED_ACCOUNT_ID` is a guard — the connector aborts if the authenticated
account differs, so it cannot accidentally run somewhere unintended.

## Run

```bash
python -m src.main
```

Outputs land in `output/`, which is gitignored. Raw evidence contains account
IDs, principal names and full policy documents; do not commit it.

Open `output/REPORT.html` for the human-facing demo report, or
`output/graph/graph.html` for the interactive relationship graph on its own.

## Current state

All 10 build stages implemented: authentication, IAM collection, normalization,
group inheritance, last-accessed evidence, deterministic security rules,
relationship graph, CloudTrail collection, Access Analyzer + evidence package,
and AI explanations — plus a demo report layer.
