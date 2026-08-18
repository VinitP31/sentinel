"""Demo report tests.

Presentation layer only — asserts REPORT.html reflects already-generated
outputs verbatim, embeds the existing graph.html (doesn't build a second
graph), and never mutates graph.json/findings.json/explanations.json.
"""

import base64
import copy
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
from types import SimpleNamespace

import pytest

from src.ai.explain import ModelExplanation, explain_findings
from src.analysis import rules
from src.analysis.indirect_privilege_path import find_indirect_privilege_paths
from src.evidence.build import build_evidence_package
from src.graph.build import build_graph
from src.graph.visualize import render_graph
from src.normalize.iam import normalize, resolve_group_inheritance
from src.report.build import render_report
from src.util.status import ok

FIXTURE_DIR = Path(__file__).parent / "fixtures"

VALID_EXPLANATION = ModelExplanation(
    priority="medium",
    explanation="Explanation grounded in supplied evidence.",
    supporting_evidence=["evidence item"],
    configured_access="Some configured access.",
    observed_activity="No activity observed.",
    access_path="",
    limitations=["CloudTrail covers management events only."],
    recommended_action="Scope down to least privilege.",
)


def fake_openai_client():
    client = MagicMock()
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(parsed=VALID_EXPLANATION, refusal=None))]
    )
    client.chat.completions.parse.return_value = response
    return client


@pytest.fixture
def normalized():
    raw = json.loads((FIXTURE_DIR / "raw_iam_authorization_details.json").read_text())
    return resolve_group_inheritance(normalize(raw))


@pytest.fixture
def graph(normalized):
    return build_graph(normalized)


@pytest.fixture
def last_accessed():
    return json.loads((FIXTURE_DIR / "last_accessed.json").read_text())


@pytest.fixture
def cloudtrail():
    return {
        "region": "us-east-1",
        "evidence_window": {
            "start_time": "2026-05-19T00:00:00+00:00",
            "end_time": "2026-08-17T00:00:00+00:00",
            "lookback_days": 90,
        },
        "events": [],
    }


@pytest.fixture
def analyzer_data():
    return {
        "analyzers": [
            {
                "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/POC-External-Access",
                "name": "POC-External-Access",
                "type": "ACCOUNT",
                "status": "ACTIVE",
            }
        ],
        "findings": [],
    }


@pytest.fixture
def findings(normalized, graph, last_accessed, cloudtrail):
    found = rules.run_all(normalized, last_accessed, cloudtrail)
    found += find_indirect_privilege_paths(graph, normalized)
    return found


@pytest.fixture
def evidence_package(normalized, graph, last_accessed, cloudtrail, analyzer_data):
    return build_evidence_package(normalized, graph, last_accessed, cloudtrail, analyzer_data, "us-east-1")


@pytest.fixture
def explanations(findings, evidence_package):
    result, _status = explain_findings(findings, evidence_package, client=fake_openai_client())
    return result


@pytest.fixture
def identity():
    return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/poc-collector", "region": "us-east-1"}


@pytest.fixture
def statuses():
    return [ok("iam_configuration", {"users": 3}), ok("cloudtrail_event_history", {"events": 0})]


@pytest.fixture
def graph_html_path(graph, findings, tmp_path):
    return render_graph(graph, findings, tmp_path / "graph.html")


@pytest.fixture
def context(identity, normalized, findings, evidence_package, explanations, analyzer_data, last_accessed, cloudtrail, statuses):
    return {
        "identity": identity,
        "normalized": normalized,
        "findings": findings,
        "evidence_package": evidence_package,
        "explanations": explanations,
        "analyzer_data": analyzer_data,
        "last_accessed_data": last_accessed,
        "last_accessed_statuses": statuses,
        "cloudtrail_data": cloudtrail,
        "statuses": statuses,
        "finished": datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc),
    }


def test_report_html_created(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    assert output.exists()
    assert output.stat().st_size > 0


def test_account_id_and_region_appear(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert context["identity"]["account_id"] in content
    assert context["identity"]["region"] in content


def test_all_findings_represented(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    for finding in context["findings"]:
        assert finding["principal"]["name"] in content
        if finding["rule"] == "potentially_unused_access":
            # compact table row, not the full sentence — by design, per the
            # "don't give every unused-access finding a huge card" redesign
            from src.report.build import _friendly_name

            assert _friendly_name(finding["policy_id"]) in content
        else:
            # detail text is HTML-escaped in the report (e.g. "->" -> "-&gt;")
            assert html.escape(finding["detail"], quote=False) in content


def test_all_ai_explanations_represented(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    for explanation in context["explanations"]:
        assert explanation["explanation"] in content
        assert explanation["recommended_action"] in content


def test_evidence_limitations_represented(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    packages = list(context["evidence_package"]["packages"].values())
    for limitation in packages[0]["evidence_limitations"]:
        assert limitation in content


def test_graph_visualization_embedded(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert "data:text/html;charset=utf-8;base64," in content
    # the embedded payload decodes back to the original graph.html content
    start = content.index("base64,") + len("base64,")
    end = content.index('"', start)
    decoded = base64.b64decode(content[start:end]).decode("utf-8")
    assert decoded == graph_html_path.read_text()


def test_security_view_and_full_graph_available_in_embedded_graph(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    start = content.index("base64,") + len("base64,")
    end = content.index('"', start)
    decoded = base64.b64decode(content[start:end]).decode("utf-8")
    assert "showSecurityView" in decoded
    assert "showFullGraph" in decoded
    assert 'id="btn-security"' in decoded
    assert 'id="btn-full"' in decoded


def test_no_external_cdn_or_network_dependency(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert "http://" not in content
    assert "https://" not in content


def test_source_graph_json_shape_unchanged(graph, findings, tmp_path):
    import networkx as nx

    before = copy.deepcopy(dict(graph.nodes(data=True)))
    render_graph(graph, findings, tmp_path / "graph.html")
    after = dict(graph.nodes(data=True))
    assert before == after


def test_findings_list_unchanged_by_report(context, graph_html_path, tmp_path):
    before = copy.deepcopy(context["findings"])
    render_report(context, graph_html_path, tmp_path / "REPORT.html")
    assert context["findings"] == before


def test_explanations_list_unchanged_by_report(context, graph_html_path, tmp_path):
    before = copy.deepcopy(context["explanations"])
    render_report(context, graph_html_path, tmp_path / "REPORT.html")
    assert context["explanations"] == before


def test_navigation_sections_present(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    for anchor in ("#summary", "#findings", "#graph", "#principals", "#activity", "#limitations"):
        assert f'href="{anchor}"' in content


def test_bob_group_inherited_vs_charlie_direct_visible(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert "group_inherited" in content
    assert "direct_attached" in content
    assert "Auditors" in content


def test_evidence_package_not_mutated_by_report(context, graph_html_path, tmp_path):
    before = copy.deepcopy(context["evidence_package"])
    render_report(context, graph_html_path, tmp_path / "REPORT.html")
    assert context["evidence_package"] == before


def test_key_risk_shows_escalation_chain(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert "Key Risk" in content
    assert "alice" in content
    assert "DeveloperRole" in content
    assert "AdminRole" in content
    assert "indirectly reach" in content


def test_findings_sorted_by_priority_order(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    findings_section = content[content.index('id="findings"') : content.index('id="graph"')]
    # indirect_privilege_path / administrative_access / broad_permission cards
    # must all appear before the collapsed unused-access table.
    escalation_pos = findings_section.find("Privilege Escalation Path")
    admin_pos = findings_section.find("Administrative Access")
    broad_pos = findings_section.find("Broad Permission")
    unused_pos = findings_section.find("Potentially Unused Access")
    assert -1 not in (escalation_pos, admin_pos, broad_pos, unused_pos)
    assert escalation_pos < unused_pos
    assert admin_pos < unused_pos
    assert broad_pos < unused_pos


def test_deterministic_and_ai_labels_distinct(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert "DETERMINISTIC FINDING" in content
    assert "AI EXPLANATION" in content
    # the old verbose per-card label must be gone
    assert "AI Explanation (Stage 10" not in content


def test_unused_access_is_a_compact_table_not_cards(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert 'class="unused-table"' in content
    assert "<table" in content
    assert "No activity observed" in content


def test_tooltips_present_for_technical_terms(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    assert 'title="Can assume this IAM role"' in content
    assert "Permission comes through a group membership" in content
    assert "Policy is attached directly to this principal" in content


def test_priority_principals_marked_and_listed_first(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    principals_section = content[content.index('id="principals"') : content.index('id="activity"')]
    alice_pos = principals_section.find("alice")
    developer_pos = principals_section.find("DeveloperRole")
    service_linked_pos = principals_section.find("AWS service-linked roles")
    assert alice_pos != -1
    assert developer_pos != -1
    if service_linked_pos != -1:
        assert alice_pos < service_linked_pos
        assert developer_pos < service_linked_pos


def test_limitations_appear_exactly_once(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    packages = list(context["evidence_package"]["packages"].values())
    first_limitation = packages[0]["evidence_limitations"][0]
    assert content.count(html.escape(first_limitation, quote=False)) == 1


def test_friendly_policy_names_used_in_compact_cards(context, graph_html_path, tmp_path):
    output = render_report(context, graph_html_path, tmp_path / "REPORT.html")
    content = output.read_text()
    findings_section = content[content.index('id="findings"') : content.index('id="graph"')]
    assert "POC-Admin-Access" in findings_section
    # the full ARN should not appear outside a collapsed evidence toggle
    visible_part = findings_section.split('<details class="evidence-toggle">')[0]
    assert "arn:aws:iam::" not in visible_part
