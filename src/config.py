"""Configuration, read once from the environment.

No account ID, ARN, region or path should be hard-coded anywhere else.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# AWS
AWS_PROFILE_NAME: str | None = os.getenv("AWS_PROFILE_NAME") or None
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

# Safety guard. If set, the connector aborts when the authenticated account
# does not match. Prevents an accidental run against the wrong account.
EXPECTED_ACCOUNT_ID: str | None = os.getenv("EXPECTED_ACCOUNT_ID") or None

# CloudTrail Event History retains 90 days; values above that are pointless.
CLOUDTRAIL_LOOKBACK_DAYS: int = min(int(os.getenv("CLOUDTRAIL_LOOKBACK_DAYS", "90")), 90)

# AI layer. Never used to authenticate to AWS — this key only talks to
# OpenAI's API.
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Output
OUTPUT_DIR = PROJECT_ROOT / "output"
RAW_DIR = OUTPUT_DIR / "raw"
NORMALIZED_DIR = OUTPUT_DIR / "normalized"
GRAPH_DIR = OUTPUT_DIR / "graph"
FINDINGS_DIR = OUTPUT_DIR / "findings"
EVIDENCE_DIR = OUTPUT_DIR / "evidence"
AI_DIR = OUTPUT_DIR / "ai"
REPORT_PATH = OUTPUT_DIR / "REPORT.html"


# Account-scoped output paths. With no account_label, every function below
# resolves to exactly the constants above (OUTPUT_DIR/RAW_DIR/etc) — the
# single-account CLI path is unaffected. With a label (e.g. "PROD"), output
# is rooted under OUTPUT_DIR/<account_label>/ instead, so multiple accounts
# can be audited into separate trees without colliding.
def account_output_root(account_label: str | None = None) -> Path:
    return OUTPUT_DIR if account_label is None else OUTPUT_DIR / account_label


def raw_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "raw"


def normalized_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "normalized"


def graph_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "graph"


def findings_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "findings"


def evidence_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "evidence"


def ai_dir(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "ai"


def report_path(account_label: str | None = None) -> Path:
    return account_output_root(account_label) / "REPORT.html"
