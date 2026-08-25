"""Entry point. Runs the pipeline end to end and writes each stage's output to disk."""

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes}m {secs}s"


def _ok(summary: str = "", duration_seconds: float | None = None) -> None:
    print(f"  ✓ OK{'  ' + summary if summary else ''}")
    if duration_seconds is not None:
        print(f"  Duration: {_format_duration(duration_seconds)}")


def _failed(error: str, duration_seconds: float | None = None) -> None:
    print(f"  ✗ FAILED — {error}", file=sys.stderr)
    if duration_seconds is not None:
        print(f"  Duration: {_format_duration(duration_seconds)}")


def _prompt(label: str, default: str, empty_hint: str = "") -> str:
    shown = default or empty_hint
    answer = input(f"  {label} [{shown}]: ").strip()
    return answer or default


TOTAL_PIPELINE_STAGES = 9  # the stages run_pipeline itself executes; stage 1 (auth) happens outside it


def run_pipeline(session, identity: dict, output_dir: Path, progress_callback=None) -> dict:
    """Run stages 2-10 of the audit against an already-authenticated session.

    Callable for any boto3.Session — profile-based or assumed-role — since
    every collector already only needs a session, not how it was built.
    Writes exactly the same files as before this function existed, rooted
    under output_dir instead of the fixed module-level config paths, so a
    caller can point multiple independent runs at separate output trees.

    progress_callback, if given, is called as
    progress_callback(stage_number, total_stages, stage_name, status=..., duration_seconds=...)
    at the same points _stage()/_ok()/_failed() already print to the
    terminal — purely additive, changes no pipeline behavior, decision, or
    output file. status is "running", "completed", or "failed".
    """
    started = datetime.now(timezone.utc)
    pipeline_started_at = time.perf_counter()
    statuses: list[CollectionStatus] = []
    stage_timings: list[dict] = []

    raw_dir = output_dir / "raw"
    normalized_dir = output_dir / "normalized"
    graph_dir = output_dir / "graph"
    findings_dir = output_dir / "findings"
    evidence_dir = output_dir / "evidence"
    ai_dir = output_dir / "ai"
    report_path = output_dir / "REPORT.html"

    result: dict = {"identity": identity}

    def _record_stage(name: str, stage_start: float) -> float:
        duration = time.perf_counter() - stage_start
        stage_timings.append({"stage": name, "duration_seconds": duration})
        return duration

    def _notify(stage_number: int, stage_name: str, status: str, duration_seconds: float | None = None) -> None:
        if progress_callback is not None:
            progress_callback(stage_number, TOTAL_PIPELINE_STAGES, stage_name, status=status, duration_seconds=duration_seconds)

    _stage(2, "IAM Configuration Collection")
    _notify(2, "IAM Configuration Collection", "running")
    stage_start = time.perf_counter()
    raw_iam, status = iam_collector.collect(session)
    statuses.append(status)

    if status.succeeded:
        path = write_json(raw_dir / "iam_authorization_details.json", raw_iam)
        for section, count in status.record_counts.items():
            print(f"  {section}: {count}")
        print(f"  Pages fetched: {status.pages_fetched}")
        iam_duration = _record_stage("IAM Configuration Collection", stage_start)
        _ok(f"-> {path.relative_to(config.PROJECT_ROOT)}", iam_duration)
        _notify(2, "IAM Configuration Collection", "completed", iam_duration)

        _stage(3, "IAM Normalization")
        _notify(3, "IAM Normalization", "running")
        stage_start = time.perf_counter()
        normalized = normalize(raw_iam)
        print(f"  policies: {len(normalized['policies'])}, permissions: {len(normalized['permissions'])}")
        print(f"  attachments (direct/inline): {len(normalized['attachments'])}")
        normalization_duration = _record_stage("IAM Normalization", stage_start)
        _ok(duration_seconds=normalization_duration)
        _notify(3, "IAM Normalization", "completed", normalization_duration)

        # Resolves group-inherited access on top of the same attachment model.
        _stage(4, "Group Inheritance")
        _notify(4, "Group Inheritance", "running")
        stage_start = time.perf_counter()
        normalized = resolve_group_inheritance(normalized)
        normalized_path = write_json(normalized_dir / "iam.json", normalized)
        print(f"  memberships: {len(normalized['memberships'])}")
        print(f"  attachments (incl. group-inherited): {len(normalized['attachments'])}")
        group_inheritance_duration = _record_stage("Group Inheritance", stage_start)
        _ok(f"-> {normalized_path.relative_to(config.PROJECT_ROOT)}", group_inheritance_duration)
        _notify(4, "Group Inheritance", "completed", group_inheritance_duration)

        # One last-accessed job per user/role.
        _stage(5, "Last Accessed Evidence")
        _notify(5, "Last Accessed Evidence", "running")
        stage_start = time.perf_counter()
        principals = [
            {"id": p["id"], "name": p["name"], "type": p["type"]}
            for p in normalized["users"] + normalized["roles"]
        ]
        last_accessed_data, last_accessed_statuses = last_accessed_collector.collect(session, principals)
        statuses.extend(last_accessed_statuses)

        succeeded = sum(1 for s in last_accessed_statuses if s.succeeded)
        last_accessed_path = write_json(raw_dir / "last_accessed.json", last_accessed_data)
        for s in last_accessed_statuses:
            if not s.succeeded:
                _failed(f"{s.source}: {s.error}")
        last_accessed_duration = _record_stage("Last Accessed Evidence", stage_start)
        _ok(
            f"{succeeded}/{len(last_accessed_statuses)} principals -> {last_accessed_path.relative_to(config.PROJECT_ROOT)}",
            last_accessed_duration,
        )
        _notify(
            5,
            "Last Accessed Evidence",
            "completed" if succeeded == len(last_accessed_statuses) else "failed",
            last_accessed_duration,
        )

        # Built from normalized data only.
        _stage(7, "Relationship Graph")
        _notify(7, "Relationship Graph", "running")
        stage_start = time.perf_counter()
        graph = build_graph(normalized)
        graph_path = write_json(graph_dir / "graph.json", nx.node_link_data(graph))
        print(f"  nodes: {graph.number_of_nodes()}, edges: {graph.number_of_edges()}")
        relationship_graph_duration = _record_stage("Relationship Graph", stage_start)
        _ok(f"-> {graph_path.relative_to(config.PROJECT_ROOT)}", relationship_graph_duration)
        _notify(7, "Relationship Graph", "completed", relationship_graph_duration)

        # One account-wide sweep, not per-principal.
        _stage(8, "CloudTrail Event History")
        _notify(8, "CloudTrail Event History", "running")
        stage_start = time.perf_counter()
        cloudtrail_data, cloudtrail_status = cloudtrail_collector.collect(session, config.CLOUDTRAIL_LOOKBACK_DAYS)
        statuses.append(cloudtrail_status)

        cloudtrail_path = write_json(raw_dir / "cloudtrail_events.json", cloudtrail_data)
        cloudtrail_duration = _record_stage("CloudTrail Event History", stage_start)
        if cloudtrail_status.succeeded:
            window = cloudtrail_data["evidence_window"]
            print(f"  region: {cloudtrail_data['region']}, lookback: {window['lookback_days']} days")
            _ok(
                f"{cloudtrail_status.record_counts['events']} events -> {cloudtrail_path.relative_to(config.PROJECT_ROOT)}",
                cloudtrail_duration,
            )
            _notify(8, "CloudTrail Event History", "completed", cloudtrail_duration)
        else:
            _failed(cloudtrail_status.error, cloudtrail_duration)
            _notify(8, "CloudTrail Event History", "failed", cloudtrail_duration)

        # Needs the last-accessed, graph and CloudTrail evidence above, hence
        # printed after them here.
        _stage(6, "Deterministic Security Analysis")
        _notify(6, "Deterministic Security Analysis", "running")
        stage_start = time.perf_counter()
        findings = rules.run_all(normalized, last_accessed_data, cloudtrail_data)

        # Indirect privilege path also needs the graph, evaluated here
        # alongside the rest of the deterministic findings.
        findings += find_indirect_privilege_paths(graph, normalized)

        findings_path = write_json(findings_dir / "findings.json", findings)
        by_rule: dict[str, int] = {}
        for finding in findings:
            by_rule[finding["rule"]] = by_rule.get(finding["rule"], 0) + 1
        for rule_name, count in by_rule.items():
            print(f"  {rule_name}: {count}")
        deterministic_analysis_duration = _record_stage("Deterministic Security Analysis", stage_start)
        _ok(
            f"{len(findings)} findings -> {findings_path.relative_to(config.PROJECT_ROOT)}",
            deterministic_analysis_duration,
        )
        _notify(6, "Deterministic Security Analysis", "completed", deterministic_analysis_duration)

        # Demo visualization — simple risk overview, colored by the findings
        # above. Renders the same graph object, never mutates it.
        graph_html_path = render_graph(graph, findings, graph_dir / "graph.html")
        print(f"  visualization -> {graph_html_path.relative_to(config.PROJECT_ROOT)}")

        # External-access findings, then the per-principal evidence package.
        _stage(9, "Access Analyzer & Evidence Package")
        _notify(9, "Access Analyzer & Evidence Package", "running")
        stage_start = time.perf_counter()
        analyzer_data, analyzer_status = access_analyzer_collector.collect(session)
        statuses.append(analyzer_status)

        analyzer_path = write_json(raw_dir / "access_analyzer.json", analyzer_data)
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
        evidence_path = write_json(evidence_dir / "evidence_package.json", evidence_package)
        print(f"  evidence packages: {len(evidence_package['packages'])}")
        access_analyzer_duration = _record_stage("Access Analyzer & Evidence Package", stage_start)
        _ok(
            f"-> {analyzer_path.relative_to(config.PROJECT_ROOT)}, {evidence_path.relative_to(config.PROJECT_ROOT)}",
            access_analyzer_duration,
        )
        _notify(
            9,
            "Access Analyzer & Evidence Package",
            "completed" if analyzer_status.succeeded else "failed",
            access_analyzer_duration,
        )

        # AI explanations of the findings above — findings.json itself is only read, never modified here.
        _stage(10, "AI Security Explanation")
        _notify(10, "AI Security Explanation", "running")
        stage_start = time.perf_counter()
        explanations, ai_status = explain_findings(findings, evidence_package)
        statuses.append(ai_status)

        explanations_path = write_json(ai_dir / "explanations.json", explanations)
        write_json(ai_dir / "ai_status.json", ai_status.as_dict())

        ai_duration = _record_stage("AI Security Explanation", stage_start)
        if ai_status.succeeded:
            _ok(f"{ai_status.record_counts['explanations']} explanations -> {explanations_path.relative_to(config.PROJECT_ROOT)}", ai_duration)
            _notify(10, "AI Security Explanation", "completed", ai_duration)
        else:
            _failed(ai_status.error, ai_duration)
            print(f"  ({len(explanations)} explanation(s) generated before the failure)", file=sys.stderr)
            _notify(10, "AI Security Explanation", "failed", ai_duration)

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
        rendered_report_path = render_report(report_context, graph_html_path, report_path)

        total_duration = time.perf_counter() - pipeline_started_at
        _header("AUDIT COMPLETE")
        print(f"  Report (open this): {rendered_report_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Graph (data)      : {graph_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Graph (visual)    : {graph_html_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Findings          : {findings_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Evidence package  : {evidence_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  AI explanations   : {explanations_path.relative_to(config.PROJECT_ROOT)}")
        print(f"  Total audit time  : {_format_duration(total_duration)}")
        print()

        result.update(
            {
                "findings_path": findings_path,
                "report_path": rendered_report_path,
                "graph_path": graph_path,
                "graph_html_path": graph_html_path,
                "evidence_path": evidence_path,
                "explanations_path": explanations_path,
                "finding_count": len(findings),
            }
        )
    else:
        iam_failure_duration = _record_stage("IAM Configuration Collection", stage_start)
        _failed(f"IAM collection: {status.error}", iam_failure_duration)
        _notify(2, "IAM Configuration Collection", "failed", iam_failure_duration)

    # A run with gaps must be distinguishable from a complete one.
    collection_report = {
        "started_at": started,
        "finished_at": datetime.now(timezone.utc),
        "identity": identity,
        "complete": all(s.succeeded for s in statuses),
        "sources": [s.as_dict() for s in statuses],
    }
    write_json(findings_dir / "collection_report.json", collection_report)

    result["complete"] = collection_report["complete"]
    result["statuses"] = statuses
    result["timings"] = {
        "stages": stage_timings,
        "total_duration_seconds": time.perf_counter() - pipeline_started_at,
    }
    return result


def run() -> int:
    _header("AWS IAM SECURITY AUDIT")

    print("Target account (press Enter to keep the .env default)")
    profile_name = _prompt("AWS profile name", config.AWS_PROFILE_NAME or "", "default credential chain") or None
    region_name = _prompt("AWS region", config.AWS_REGION)
    expected_account_id = _prompt("Expected account ID (optional)", config.EXPECTED_ACCOUNT_ID or "", "none") or None

    _stage(1, "Authentication & Account Verification")
    stage_start = time.perf_counter()
    try:
        session = auth.get_session(profile_name, region_name)
        identity = auth.verify_identity(session, expected_account_id)
    except auth.AuthError as exc:
        _failed(str(exc), time.perf_counter() - stage_start)
        return 1

    print(f"  Profile     : {profile_name or '(default credential chain)'}")
    print(f"  Account ID  : {identity['account_id']}")
    print(f"  Identity    : {identity['arn']}")
    print(f"  Region      : {identity['region']}")
    _ok("connected", time.perf_counter() - stage_start)

    result = run_pipeline(session, identity, config.OUTPUT_DIR)

    return 0 if result["complete"] else 2


if __name__ == "__main__":
    sys.exit(run())
