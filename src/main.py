"""Entry point. Runs the pipeline end to end and writes each stage's output to disk."""

import sys
from datetime import datetime, timezone

import networkx as nx

from src import config
from src.ai.explain import explain_findings
from src.analysis import rules
from src.analysis.indirect_privilege_path import find_indirect_privilege_paths
from src.aws import access_analyzer_collector, auth, cloudtrail_collector, iam_collector, last_accessed_collector
from src.evidence.build import build_evidence_package
from src.graph.build import build_graph
from src.graph.visualize import render_graph
from src.normalize.iam import normalize, resolve_group_inheritance
from src.report.build import render_report
from src.util.io import write_json
from src.util.status import CollectionStatus

WIDTH = 66


def _rule(char: str = "=") -> None:
    print(char * WIDTH)


def _header(title: str) -> None:
    print()
    _rule("=")
    print(title.center(WIDTH))
    _rule("=")


def _stage(number: int, title: str) -> None:
    print()
    print(f"[{number}/10] {title}")
    _rule("-")


def _ok(summary: str = "") -> None:
    print(f"  ✓ OK{'  ' + summary if summary else ''}")


def _failed(error: str) -> None:
    print(f"  ✗ FAILED — {error}", file=sys.stderr)


def run() -> int:
    started = datetime.now(timezone.utc)
    statuses: list[CollectionStatus] = []

    _header("AWS IAM SECURITY AUDIT")

    _stage(1, "Authentication & Account Verification")
    try:
        session = auth.get_session()
        identity = auth.verify_identity(session)
    except auth.AuthError as exc:
        _failed(str(exc))
        return 1

    print(f"  Profile     : {config.AWS_PROFILE_NAME or '(default credential chain)'}")
    print(f"  Account ID  : {identity['account_id']}")
    print(f"  Identity    : {identity['arn']}")
    print(f"  Region      : {identity['region']}")
    _ok("connected")

    _stage(2, "IAM Configuration Collection")
    raw_iam, status = iam_collector.collect(session)
    statuses.append(status)

    if status.succeeded:
        path = write_json(config.RAW_DIR / "iam_authorization_details.json", raw_iam)
        for section, count in status.record_counts.items():
            print(f"  {section}: {count}")
        print(f"  Pages fetched: {status.pages_fetched}")
        _ok(f"-> {path.relative_to(config.PROJECT_ROOT)}")

        _stage(3, "IAM Normalization")
        normalized = normalize(raw_iam)
        print(f"  policies: {len(normalized['policies'])}, permissions: {len(normalized['permissions'])}")
        print(f"  attachments (direct/inline): {len(normalized['attachments'])}")
        _ok()

        # Resolves group-inherited access on top of the same attachment model.
        _stage(4, "Group Inheritance")
        normalized = resolve_group_inheritance(normalized)
        normalized_path = write_json(config.NORMALIZED_DIR / "iam.json", normalized)
        print(f"  memberships: {len(normalized['memberships'])}")
        print(f"  attachments (incl. group-inherited): {len(normalized['attachments'])}")
        _ok(f"-> {normalized_path.relative_to(config.PROJECT_ROOT)}")

        # One last-accessed job per user/role.
        _stage(5, "Last Accessed Evidence")
        principals = [
            {"id": p["id"], "name": p["name"], "type": p["type"]}
            for p in normalized["users"] + normalized["roles"]
        ]
        last_accessed_data, last_accessed_statuses = last_accessed_collector.collect(session, principals)
        statuses.extend(last_accessed_statuses)

        succeeded = sum(1 for s in last_accessed_statuses if s.succeeded)
        last_accessed_path = write_json(config.RAW_DIR / "last_accessed.json", last_accessed_data)
        for s in last_accessed_statuses:
            if not s.succeeded:
                _failed(f"{s.source}: {s.error}")
        _ok(f"{succeeded}/{len(last_accessed_statuses)} principals -> {last_accessed_path.relative_to(config.PROJECT_ROOT)}")

        # Built from normalized data only.
        _stage(7, "Relationship Graph")
        graph = build_graph(normalized)
        graph_path = write_json(config.GRAPH_DIR / "graph.json", nx.node_link_data(graph))
        print(f"  nodes: {graph.number_of_nodes()}, edges: {graph.number_of_edges()}")
        _ok(f"-> {graph_path.relative_to(config.PROJECT_ROOT)}")

        # One account-wide sweep, not per-principal.
        _stage(8, "CloudTrail Event History")
        cloudtrail_data, cloudtrail_status = cloudtrail_collector.collect(session, config.CLOUDTRAIL_LOOKBACK_DAYS)
        statuses.append(cloudtrail_status)

        cloudtrail_path = write_json(config.RAW_DIR / "cloudtrail_events.json", cloudtrail_data)
        if cloudtrail_status.succeeded:
            window = cloudtrail_data["evidence_window"]
            print(f"  region: {cloudtrail_data['region']}, lookback: {window['lookback_days']} days")
            _ok(f"{cloudtrail_status.record_counts['events']} events -> {cloudtrail_path.relative_to(config.PROJECT_ROOT)}")
        else:
            _failed(cloudtrail_status.error)

        # Needs the last-accessed, graph and CloudTrail evidence above, hence
        # printed after them here.
        _stage(6, "Deterministic Security Analysis")
        findings = rules.run_all(normalized, last_accessed_data, cloudtrail_data)

        # Indirect privilege path also needs the graph, evaluated here
        # alongside the rest of the deterministic findings.
        findings += find_indirect_privilege_paths(graph, normalized)

        findings_path = write_json(config.FINDINGS_DIR / "findings.json", findings)
        by_rule: dict[str, int] = {}
        for finding in findings:
            by_rule[finding["rule"]] = by_rule.get(finding["rule"], 0) + 1
        for rule_name, count in by_rule.items():
            print(f"  {rule_name}: {count}")
        _ok(f"{len(findings)} findings -> {findings_path.relative_to(config.PROJECT_ROOT)}")

        # Demo visualization — simple risk overview, colored by the findings
        # above. Renders the same graph object, never mutates it.
        graph_html_path = render_graph(graph, findings, config.GRAPH_DIR / "graph.html")
        print(f"  visualization -> {graph_html_path.relative_to(config.PROJECT_ROOT)}")

        # External-access findings, then the per-principal evidence package.
        _stage(9, "Access Analyzer & Evidence Package")
        analyzer_data, analyzer_status = access_analyzer_collector.collect(session)
        statuses.append(analyzer_status)

        analyzer_path = write_json(config.RAW_DIR / "access_analyzer.json", analyzer_data)
        if analyzer_status.succeeded:
            print(
                f"  Access Analyzer: {analyzer_status.record_counts['analyzers']} active analyzer(s), "
                f"{analyzer_status.record_counts['findings']} findings"
            )
        else:
            _failed(f"Access Analyzer: {analyzer_status.error}")

        evidence_package = build_evidence_package(
            normalized, graph, last_accessed_data, cloudtrail_data, analyzer_data, identity["region"]
        )
        evidence_path = write_json(config.EVIDENCE_DIR / "evidence_package.json", evidence_package)
        print(f"  evidence packages: {len(evidence_package['packages'])}")
        _ok(f"-> {analyzer_path.relative_to(config.PROJECT_ROOT)}, {evidence_path.relative_to(config.PROJECT_ROOT)}")

        # AI explanations of the findings above — findings.json itself is only read, never modified here.
        _stage(10, "AI Security Explanation")
        explanations, ai_status = explain_findings(findings, evidence_package)
        statuses.append(ai_status)

        explanations_path = write_json(config.AI_DIR / "explanations.json", explanations)
        write_json(config.AI_DIR / "ai_status.json", ai_status.as_dict())

        if ai_status.succeeded:
            _ok(f"{ai_status.record_counts['explanations']} explanations -> {explanations_path.relative_to(config.PROJECT_ROOT)}")
        else:
            _failed(ai_status.error)
            print(f"  ({len(explanations)} explanation(s) generated before the failure)", file=sys.stderr)

        # Demo report — presentation only; reads outputs already written above, recomputes nothing.
        report_context = {
            "identity": identity,
            "normalized": normalized,
            "findings": findings,
            "evidence_package": evidence_package,
            "explanations": explanations,
            "analyzer_data": analyzer_data,
            "last_accessed_data": last_accessed_data,
            "last_accessed_statuses": last_accessed_statuses,
            "cloudtrail_data": cloudtrail_data,
            "statuses": statuses,
            "finished": datetime.now(timezone.utc),
        }
        report_path = render_report(report_context, graph_html_path, config.REPORT_PATH)

        _header("AUDIT COMPLETE")
        print(f"  Report (open this): {report_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Graph (data)      : {graph_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Graph (visual)    : {graph_html_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Findings          : {findings_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Evidence package  : {evidence_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  AI explanations   : {explanations_path.relative_to(config.PROJECT_ROOT)}")
        print()
    else:
        _failed(f"IAM collection: {status.error}")

    # A run with gaps must be distinguishable from a complete one.
    report = {
        "started_at": started,
        "finished_at": datetime.now(timezone.utc),
        "identity": identity,
        "complete": all(s.succeeded for s in statuses),
        "sources": [s.as_dict() for s in statuses],
    }
    write_json(config.FINDINGS_DIR / "collection_report.json", report)

    return 0 if report["complete"] else 2


if __name__ == "__main__":
    sys.exit(run())
