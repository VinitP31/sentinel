"""AI explanation layer (Stage 10).

Explains deterministic findings (src/analysis/) using each finding's own
principal's evidence package (src/evidence/) — nothing else. Never has AWS
access: no boto3 import, no AWS credentials, no AWS call of any kind. Never
decides whether something is a finding; findings.json is read here, never
written.

finding_id, rule, and principal are taken directly from the deterministic
finding and injected into the output by this code — the model is never
asked to reproduce them, so it cannot introduce a transcription error into
identifying fields. The model only fills in the explanatory fields, and only
from the finding plus that one principal's evidence package.
"""

import hashlib
import json
from typing import Literal

from openai import OpenAI, OpenAIError
from pydantic import BaseModel

from src import config
from src.util.status import CollectionStatus, failed, ok

SOURCE = "ai_explanations"

SYSTEM_PROMPT = """You explain a single already-decided IAM security finding from an audit \
connector. The finding was produced by deterministic code and is not open for \
reinterpretation — you never decide whether it is valid, never dismiss it, and \
never invent a different one.

You will receive exactly two things: the finding itself, and the evidence \
package for the one principal that finding is about. Use only what is in \
these two objects. Do not invent permissions, users, roles, activity, \
relationships, or evidence that is not present in the supplied data.

Rules:
- If the finding's rule is "potentially_unused_access", never say the access \
  was "never used" or state its non-use as a proven fact. Say only that no \
  corresponding activity was observed in the collected evidence, and note \
  that absence of observed activity is not proof the access is unnecessary.
- If the evidence package shows attachment_type "group_inherited" with a \
  source_group_name, always name that group explicitly — never describe \
  inherited access as if it were direct.
- If the evidence package's relationships include a CAN_ASSUME chain \
  relevant to this finding (e.g. alice -> DeveloperRole -> AdminRole), \
  describe that actual chain and explain why the chain's endpoint has the \
  access described in the finding.
- Always take evidence_limitations in the package into account — qualify \
  your explanation using them rather than ignoring them.
- If a requested field has nothing applicable in the supplied evidence, \
  return an empty string or empty list for it — do not fabricate content to \
  fill it.
- priority reflects only the ordering/emphasis warranted by the supplied \
  finding and evidence — it is not a new severity classification and must \
  not contradict or override the fact that the finding already exists.
- recommended_action should be a practical least-privilege suggestion \
  grounded in what configured_access and attribution actually show.
"""


class ModelExplanation(BaseModel):
    priority: Literal["high", "medium", "low"]
    explanation: str
    supporting_evidence: list[str]
    configured_access: str
    observed_activity: str
    access_path: str
    limitations: list[str]
    recommended_action: str


def _finding_id(finding: dict) -> str:
    """Stable deterministic id derived from the finding's own fields.

    findings.json has no explicit id field and is never modified to add
    one — this is computed here, on the side, from what already
    uniquely identifies a finding (rule + principal + policy).
    """
    key = f"{finding['rule']}|{finding['principal']['id']}|{finding.get('policy_id', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _prompt_payload(finding: dict, principal_package: dict) -> str:
    return json.dumps({"finding": finding, "principal_evidence": principal_package}, default=str)


def explain_findings(
    findings: list[dict],
    evidence_package: dict,
    client: OpenAI | None = None,
) -> tuple[list[dict], CollectionStatus]:
    """Produce one validated explanation per finding.

    Zero findings is a successful, empty result — not a failure. Stops at
    the first missing-evidence, API, or invalid-output problem and reports
    it as a failure without touching findings.json; explanations already
    produced before that point are still returned.
    """
    if not findings:
        return [], ok(SOURCE, {"explanations": 0})

    if client is None:
        try:
            client = OpenAI(api_key=config.OPENAI_API_KEY)
        except OpenAIError as exc:
            return [], failed(SOURCE, f"could not construct OpenAI client: {exc}")

    packages = evidence_package.get("packages", {})
    explanations: list[dict] = []

    for finding in findings:
        principal_id = finding["principal"]["id"]
        finding_id = _finding_id(finding)
        principal_package = packages.get(principal_id)

        if principal_package is None:
            return explanations, failed(
                SOURCE, f"missing evidence package for principal {principal_id} (finding {finding_id})"
            )

        try:
            response = client.chat.completions.parse(
                model=config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _prompt_payload(finding, principal_package)},
                ],
                response_format=ModelExplanation,
            )
        except OpenAIError as exc:
            return explanations, failed(SOURCE, f"OpenAI API error for finding {finding_id}: {exc}")

        message = response.choices[0].message
        if message.parsed is None:
            return explanations, failed(
                SOURCE, f"model returned invalid/refused output for finding {finding_id}: {message.refusal}"
            )

        explanations.append(
            {
                "finding_id": finding_id,
                "rule": finding["rule"],
                "principal": finding["principal"],
                **message.parsed.model_dump(),
            }
        )

    return explanations, ok(SOURCE, {"explanations": len(explanations)})
