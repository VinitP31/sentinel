"""AI explanation layer tests.

No real OpenAI API call anywhere — the client is a mock/fake throughout.
findings.json is never touched by this layer; these tests operate on
in-memory finding/evidence-package dicts only.
"""

import copy
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from openai import APIConnectionError, OpenAIError

from src.ai.explain import MAX_WORKERS, ModelExplanation, _finding_id, explain_findings

FIXTURE_DIR = Path(__file__).parent / "fixtures"

VALID_EXPLANATION = ModelExplanation(
    priority="medium",
    explanation="Explains the finding using only supplied evidence.",
    supporting_evidence=["evidence item"],
    configured_access="Some configured access description.",
    observed_activity="No activity observed.",
    access_path="",
    limitations=["CloudTrail covers management events only."],
    recommended_action="Scope this down to least privilege.",
)


def fake_client(parsed=VALID_EXPLANATION, refusal=None, side_effect=None):
    client = MagicMock()
    if side_effect is not None:
        client.chat.completions.parse.side_effect = side_effect
    else:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(parsed=parsed, refusal=refusal))])
        client.chat.completions.parse.return_value = response
    return client


def make_finding(rule="potentially_unused_access", principal_id="arn:aws:iam::123:user/charlie", principal_name="charlie", principal_type="user", policy_id="pol-1", **extra):
    finding = {
        "rule": rule,
        "principal": {"id": principal_id, "name": principal_name, "type": principal_type},
        "policy_id": policy_id,
        "attribution": {"attachment_type": "direct_attached"},
        "detail": "No corresponding activity observed in the collected evidence for charlie's access.",
    }
    finding.update(extra)
    return finding


def make_evidence_package(principal_id, **overrides):
    package = {
        "principal": {"id": principal_id, "name": "charlie", "type": "user"},
        "configured_access": [],
        "relationships": [],
        "observed_activity": {"evidence_window": {}, "events": []},
        "last_accessed": [],
        "analyzer_findings": [],
        "evidence_limitations": ["CloudTrail covers management events only."],
    }
    package.update(overrides)
    return {"packages": {principal_id: package}}


def test_one_finding_produces_one_explanation():
    finding = make_finding()
    evidence = make_evidence_package(finding["principal"]["id"])
    client = fake_client()

    explanations, status = explain_findings([finding], evidence, client=client)

    assert status.succeeded
    assert len(explanations) == 1
    assert explanations[0]["rule"] == "potentially_unused_access"
    assert explanations[0]["principal"] == finding["principal"]
    assert explanations[0]["finding_id"] == _finding_id(finding)


def test_finding_matched_to_correct_principal_package():
    finding = make_finding(principal_id="arn:aws:iam::123:user/alice", principal_name="alice")
    evidence = make_evidence_package("arn:aws:iam::123:user/alice")
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    sent_payload = json.loads(client.chat.completions.parse.call_args.kwargs["messages"][1]["content"])
    assert sent_payload["principal_evidence"]["principal"]["id"] == "arn:aws:iam::123:user/alice"


def test_unrelated_principal_evidence_never_sent():
    finding = make_finding(principal_id="arn:aws:iam::123:user/alice", principal_name="alice")
    evidence = make_evidence_package("arn:aws:iam::123:user/alice")
    evidence["packages"]["arn:aws:iam::123:user/bob"] = make_evidence_package("arn:aws:iam::123:user/bob")["packages"][
        "arn:aws:iam::123:user/bob"
    ]
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    sent_payload = json.loads(client.chat.completions.parse.call_args.kwargs["messages"][1]["content"])
    assert "bob" not in json.dumps(sent_payload)


def test_missing_evidence_package_is_a_failure():
    finding = make_finding(principal_id="arn:aws:iam::123:user/ghost")
    evidence = {"packages": {}}
    client = fake_client()

    explanations, status = explain_findings([finding], evidence, client=client)

    assert not status.succeeded
    assert "missing evidence package" in status.error
    assert explanations == []


def test_zero_findings_is_successful_empty_result():
    explanations, status = explain_findings([], {"packages": {}}, client=fake_client())

    assert status.succeeded
    assert explanations == []
    assert status.record_counts == {"explanations": 0}


def test_api_failure_produces_failure_status():
    finding = make_finding()
    evidence = make_evidence_package(finding["principal"]["id"])
    error = APIConnectionError(request=MagicMock())
    client = fake_client(side_effect=error)

    explanations, status = explain_findings([finding], evidence, client=client)

    assert not status.succeeded
    assert explanations == []


def test_malformed_model_output_produces_failure_status():
    finding = make_finding()
    evidence = make_evidence_package(finding["principal"]["id"])
    client = fake_client(parsed=None, refusal="could not produce valid structured output")

    explanations, status = explain_findings([finding], evidence, client=client)

    assert not status.succeeded
    assert "invalid/refused output" in status.error


def test_potentially_unused_access_prompt_forbids_never_used_wording():
    # Structural guarantee: the system prompt itself instructs the model
    # never to claim permanent non-use — verify the constraint is present
    # in what's actually sent, since we can't unit-test model behavior.
    finding = make_finding(rule="potentially_unused_access")
    evidence = make_evidence_package(finding["principal"]["id"])
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    system_message = " ".join(client.chat.completions.parse.call_args.kwargs["messages"][0]["content"].split())
    assert "never used" in system_message.lower()  # names the forbidden phrase to ban it
    assert "no corresponding activity" in system_message.lower()


def test_evidence_limitations_forwarded_in_prompt():
    finding = make_finding()
    evidence = make_evidence_package(
        finding["principal"]["id"], evidence_limitations=["A very specific limitation string."]
    )
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    sent_payload = json.loads(client.chat.completions.parse.call_args.kwargs["messages"][1]["content"])
    assert "A very specific limitation string." in sent_payload["principal_evidence"]["evidence_limitations"]


def test_group_inherited_attribution_preserved_in_prompt_payload():
    finding = make_finding(
        principal_id="arn:aws:iam::123:user/bob",
        principal_name="bob",
        attribution={"attachment_type": "group_inherited", "source_group_name": "Auditors"},
    )
    evidence = make_evidence_package(
        "arn:aws:iam::123:user/bob",
        configured_access=[
            {
                "policy": "POC-Developer-S3-ReadOnly",
                "attachment_type": "group_inherited",
                "source_group_name": "Auditors",
                "permissions": [],
            }
        ],
    )
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    sent_payload = json.loads(client.chat.completions.parse.call_args.kwargs["messages"][1]["content"])
    assert sent_payload["finding"]["attribution"]["source_group_name"] == "Auditors"
    assert sent_payload["principal_evidence"]["configured_access"][0]["source_group_name"] == "Auditors"


def test_can_assume_path_preserved_in_prompt_payload():
    finding = make_finding(
        rule="indirect_privilege_path",
        principal_id="arn:aws:iam::123:user/alice",
        principal_name="alice",
    )
    evidence = make_evidence_package(
        "arn:aws:iam::123:user/alice",
        relationships=[
            {"from": "alice", "relationship": "CAN_ASSUME", "to": "DeveloperRole"},
            {"from": "DeveloperRole", "relationship": "CAN_ASSUME", "to": "AdminRole"},
        ],
    )
    client = fake_client()

    explain_findings([finding], evidence, client=client)

    sent_payload = json.loads(client.chat.completions.parse.call_args.kwargs["messages"][1]["content"])
    pairs = {(r["from"], r["to"]) for r in sent_payload["principal_evidence"]["relationships"]}
    assert ("alice", "DeveloperRole") in pairs
    assert ("DeveloperRole", "AdminRole") in pairs


def test_findings_json_byte_for_byte_unchanged(tmp_path):
    findings_path = FIXTURE_DIR / "findings_sample.json"
    findings = json.loads(findings_path.read_text())
    before = findings_path.read_bytes()

    evidence = make_evidence_package(findings[0]["principal"]["id"])
    explain_findings(copy.deepcopy(findings), evidence, client=fake_client())

    after = findings_path.read_bytes()
    assert before == after


def test_exactly_five_workers_configured():
    assert MAX_WORKERS == 5


def test_all_findings_processed_with_one_call_each():
    findings = [make_finding(policy_id=f"pol-{i}") for i in range(7)]
    evidence = make_evidence_package(findings[0]["principal"]["id"])
    client = fake_client()

    explanations, status = explain_findings(findings, evidence, client=client)

    assert status.succeeded
    assert len(explanations) == 7
    assert client.chat.completions.parse.call_count == 7


def test_output_order_matches_input_order_regardless_of_completion_order():
    findings = [
        make_finding(policy_id=f"pol-{i}", principal_id=f"arn:aws:iam::123:user/p{i}", principal_name=f"p{i}")
        for i in range(6)
    ]
    evidence = {"packages": {}}
    for finding in findings:
        evidence["packages"].update(make_evidence_package(finding["principal"]["id"])["packages"])

    # Deliberately complete out of order: worker N sleeps for a duration
    # inversely related to its index, so later-submitted findings finish
    # first. If the implementation returned completion order instead of
    # restoring original order, this would fail.
    completion_order = []
    lock = threading.Lock()

    def delayed_parse(*args, **kwargs):
        payload = json.loads(kwargs["messages"][1]["content"])
        principal_name = payload["finding"]["principal"]["name"]
        index = int(principal_name[1:])
        # Reverse the natural completion order relative to submission order.
        event = threading.Event()
        event.wait(timeout=(len(findings) - index) * 0.02)
        with lock:
            completion_order.append(index)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(parsed=VALID_EXPLANATION, refusal=None))]
        )

    client = MagicMock()
    client.chat.completions.parse.side_effect = delayed_parse

    explanations, status = explain_findings(findings, evidence, client=client)

    assert status.succeeded
    assert [e["principal"]["name"] for e in explanations] == [f["principal"]["name"] for f in findings]
    # Sanity check the test actually exercised out-of-order completion.
    assert completion_order != sorted(completion_order)


def test_multiple_requests_execute_concurrently():
    """Prove overlap deterministically: two workers must both be inside the
    mocked API call at the same time, synchronized with a Barrier rather
    than wall-clock timing."""
    barrier = threading.Barrier(2, timeout=5)

    def blocking_parse(*args, **kwargs):
        barrier.wait()  # only returns once both workers have reached this point
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(parsed=VALID_EXPLANATION, refusal=None))]
        )

    client = MagicMock()
    client.chat.completions.parse.side_effect = blocking_parse

    findings = [
        make_finding(policy_id=f"pol-{i}", principal_id=f"arn:aws:iam::123:user/p{i}", principal_name=f"p{i}")
        for i in range(2)
    ]
    evidence = {"packages": {}}
    for finding in findings:
        evidence["packages"].update(make_evidence_package(finding["principal"]["id"])["packages"])

    explanations, status = explain_findings(findings, evidence, client=client)

    assert status.succeeded
    assert len(explanations) == 2


def test_failure_associated_with_correct_finding_and_truncates_at_first_index():
    findings = [
        make_finding(policy_id="pol-0", principal_id="arn:aws:iam::123:user/p0", principal_name="p0"),
        make_finding(policy_id="pol-1", principal_id="arn:aws:iam::123:user/p1", principal_name="p1"),
        make_finding(policy_id="pol-2", principal_id="arn:aws:iam::123:user/p2", principal_name="p2"),
    ]
    evidence = {"packages": {}}
    for finding in findings[:2]:  # p2's evidence package deliberately missing
        evidence["packages"].update(make_evidence_package(finding["principal"]["id"])["packages"])

    client = fake_client()

    explanations, status = explain_findings(findings, evidence, client=client)

    assert not status.succeeded
    assert "p2" in status.error
    assert "missing evidence package" in status.error
    # Failure is at index 2 (last), so both earlier explanations are kept
    # and returned in original order.
    assert [e["principal"]["name"] for e in explanations] == ["p0", "p1"]


def test_no_aws_import_in_ai_layer():
    import src.ai.explain as explain_module

    source = Path(explain_module.__file__).read_text()
    assert "import boto3" not in source
    assert "from boto3" not in source
    assert "import src.aws" not in source
    assert "from src.aws" not in source
