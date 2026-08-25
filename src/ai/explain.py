"""AI explanation layer.

Explains deterministic findings (src/analysis/) using each finding's own
principal's evidence package (src/evidence/) — nothing else. Never has AWS
access: no boto3 import, no AWS credentials, no AWS call of any kind. Never
decides whether something is a finding; findings.json is read here, never
written.

finding_id, rule, and principal are taken directly from the deterministic
finding and injected into the output by this code, not reproduced by the
model — so a transcription error can't corrupt an identifying field. The
model only fills in the explanatory fields.
"""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Literal

from openai import OpenAI, OpenAIError
from pydantic import BaseModel

from src import config
from src.util.status import CollectionStatus, failed, ok

SOURCE = "ai_explanations"
MAX_WORKERS = 5

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


def _explain_one(client: OpenAI, finding: dict, packages: dict) -> dict:
    """Produce one explanation, or raise with a message identifying the finding.

    Runs in a worker thread — must not mutate any shared state.
    """
    principal_id = finding["principal"]["id"]
    finding_id = _finding_id(finding)
    principal_package = packages.get(principal_id)

    if principal_package is None:
        raise RuntimeError(f"missing evidence package for principal {principal_id} (finding {finding_id})")

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
        raise RuntimeError(f"OpenAI API error for finding {finding_id}: {exc}") from exc

    message = response.choices[0].message
    if message.parsed is None:
        raise RuntimeError(f"model returned invalid/refused output for finding {finding_id}: {message.refusal}")

    return {
        "finding_id": finding_id,
        "rule": finding["rule"],
        "principal": finding["principal"],
        **message.parsed.model_dump(),
    }


def explain_findings(
    findings: list[dict],
    evidence_package: dict,
    client: OpenAI | None = None,
) -> tuple[list[dict], CollectionStatus]:
    """Produce one validated explanation per finding.

    Zero findings is a successful, empty result — not a failure. Requests
    for all findings are submitted concurrently (bounded to MAX_WORKERS
    workers) so independent, blocking API calls overlap instead of
    serializing. Results are then reassembled in original finding order —
    completion order has no effect on the returned order.

    Failure handling is deterministic despite concurrent completion: after
    every submitted request has finished, the result set is walked in
    original finding order and the run is truncated at the *first* finding
    (by that order) that failed, exactly as the previous sequential
    implementation stopped at the first failure it encountered. Explanations
    for findings before that point are still returned; any successes that
    happened to complete for findings after it are discarded, so the
    returned list is always a prefix of the input order.
    """
    if not findings:
        return [], ok(SOURCE, {"explanations": 0})

    if client is None:
        try:
            client = OpenAI(api_key=config.OPENAI_API_KEY)
        except OpenAIError as exc:
            return [], failed(SOURCE, f"could not construct OpenAI client: {exc}")

    packages = evidence_package.get("packages", {})
    results: list[dict | None] = [None] * len(findings)
    errors: list[str | None] = [None] * len(findings)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_index = {
            executor.submit(_explain_one, client, finding, packages): index
            for index, finding in enumerate(findings)
        }
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                results[index] = future.result()
            except RuntimeError as exc:
                errors[index] = str(exc)

    first_failed_index = next((i for i, err in enumerate(errors) if err is not None), None)

    if first_failed_index is None:
        explanations = results  # every index succeeded
        return explanations, ok(SOURCE, {"explanations": len(explanations)})

    explanations = results[:first_failed_index]
    return explanations, failed(SOURCE, errors[first_failed_index])
