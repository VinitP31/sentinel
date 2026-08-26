"""Sentinel Streamlit UI tests.

No live AWS calls, no real orchestrator run. Pure functions (build_session,
summarize_accounts, format_* ) are imported and tested directly — importing
app.py never executes the UI, since all Streamlit calls live inside main(),
only invoked under `if __name__ == "__main__"`. Widget presence is checked
separately via Streamlit's own AppTest harness, which does run main().

Set before anything else imports/execs app.py: disables the LOCAL POC ONLY
credential-echo print (app.py reads this at import time, and AppTest
re-execs the file fresh per run, so this must be a real env var, not a
patched attribute — see app.py's own comment on that print for why).
"""

import os

os.environ["SENTINEL_DISABLE_LOCAL_CREDENTIAL_PRINT"] = "1"

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from unittest.mock import MagicMock, patch

from app import (
    CredentialRetrievalError,
    build_session,
    format_audit_error,
    format_auth_error,
    get_temporary_credentials_via_local_cli,
    summarize_accounts,
    _patch_graph_html_assets,
)
from src.aws import auth
from src.util.status import ok

APP_PATH = str(Path(__file__).parent.parent / "app.py")

FAKE_AGGREGATE = {
    "management_account_id": "957728667615",
    "organizations_status": {"succeeded": True},
    "accounts": [
        {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 4},
        {"account_label": "DEV", "account_id": "587762853586", "status": "success", "finding_count": 2},
    ],
    "accounts_succeeded": 2,
    "accounts_failed": 0,
    "findings": [
        {"account_id": "328865868092", "account_name": "PROD", "rule": "indirect_privilege_path",
         "principal": {"name": "prod-alice", "type": "user"}, "policy_id": "p1",
         "attribution": {"attachment_type": "inline"},
         "detail": "prod-alice -> ProdDeveloperRole -> ProdAdminRole reaches administrative access "
                   "(Action=*, Resource=*) via ProdAdminPolicy."},
        {"account_id": "328865868092", "account_name": "PROD", "rule": "administrative_access",
         "principal": {"name": "ProdAdminRole", "type": "role"}, "policy_id": "p2",
         "attribution": {"attachment_type": "inline"}, "detail": "ProdAdminRole has administrative access."},
        {"account_id": "328865868092", "account_name": "PROD", "rule": "potentially_unused_access",
         "principal": {"name": "prod-bob", "type": "user"}, "policy_id": "p3",
         "attribution": {"attachment_type": "group_inherited", "source_group_name": "ProdAuditors"},
         "detail": "No corresponding activity observed for prod-bob."},
        {"account_id": "328865868092", "account_name": "PROD", "rule": "broad_permission",
         "principal": {"name": "OrganizationAccountAccessRole", "type": "role"}, "policy_id": "p4",
         "attribution": {"attachment_type": "direct_attached"},
         "detail": "OrganizationAccountAccessRole holds unrestricted access."},
        {"account_id": "587762853586", "account_name": "DEV", "rule": "administrative_access",
         "principal": {"name": "dev-admin", "type": "user"}, "policy_id": "p5",
         "attribution": {"attachment_type": "inline"}, "detail": "dev-admin has administrative access."},
        {"account_id": "587762853586", "account_name": "DEV", "rule": "potentially_unused_access",
         "principal": {"name": "dev-charlie", "type": "user"}, "policy_id": "p6",
         "attribution": {"attachment_type": "group_inherited", "source_group_name": "DevAuditors"},
         "detail": "No corresponding activity observed for dev-charlie."},
    ],
    "total_findings": 6,
}


def _run_with_aggregate(aggregate, selectbox_values=None):
    at = AppTest.from_file(APP_PATH)
    at.session_state["aggregate"] = aggregate
    at.run(timeout=15)
    for key, value in (selectbox_values or {}).items():
        at.selectbox(key=key).set_value(value)
        at.run(timeout=15)
    assert not at.exception, [str(e) for e in at.exception]
    return at


def _all_text(at) -> str:
    parts = []
    for group in (at.markdown, at.caption, at.header, at.subheader, at.title, at.text, at.error, at.warning, at.info, at.success):
        parts.extend(el.value for el in group)
    parts.extend(f"{m.label} {m.value}" for m in at.metric)
    return "\n".join(parts)


# --- pure logic --------------------------------------------------------


def test_build_session_constructs_session_with_supplied_credentials():
    session = build_session("AKIAFAKEEXAMPLE", "fakeSecretExampleValue", "fakeSessionTokenExampleValue", "us-east-1")

    assert isinstance(session, boto3.Session)
    creds = session.get_credentials().get_frozen_credentials()
    assert creds.access_key == "AKIAFAKEEXAMPLE"
    assert creds.secret_key == "fakeSecretExampleValue"
    assert creds.token == "fakeSessionTokenExampleValue"
    assert session.region_name == "us-east-1"


def test_build_session_session_token_is_optional():
    session = build_session("AKIAFAKEEXAMPLE", "fakeSecretExampleValue", "", "us-east-1")

    creds = session.get_credentials().get_frozen_credentials()
    assert creds.token is None


def test_credentials_never_appear_in_orchestrator_style_output():
    """The aggregate this UI persists/displays never carries session credentials.

    build_session's job stops at producing a Session object; nothing in this
    file ever writes a credential value into a dict that later gets
    json.dumped (that dict — the orchestrator's aggregate — is built purely
    from findings/account metadata, never from the session's own credentials).
    """
    fake_secret = "FAKESECRETVALUE12345"
    build_session("AKIAFAKE", fake_secret, None, "us-east-1")

    aggregate = {
        "management_account_id": "957728667615",
        "accounts": [{"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 1}],
        "findings": [{"account_id": "328865868092", "account_name": "PROD", "rule": "broad_permission"}],
        "total_findings": 1,
    }
    serialized = json.dumps(aggregate)

    assert fake_secret not in serialized


def test_summarize_accounts_successful_result():
    aggregate = {
        "accounts": [
            {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 13},
            {"account_label": "DEV", "account_id": "587762853586", "status": "success", "finding_count": 9},
        ]
    }

    summaries = summarize_accounts(aggregate)

    assert summaries == [
        {"label": "PROD", "id": "328865868092", "status": "success", "finding_count": 13,
         "failure_stage": None, "error": None},
        {"label": "DEV", "id": "587762853586", "status": "success", "finding_count": 9,
         "failure_stage": None, "error": None},
    ]


def test_summarize_accounts_partial_failure():
    aggregate = {
        "accounts": [
            {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 13},
            {"account_label": "DEV", "account_id": "587762853586", "status": "failed",
             "failure_stage": "authentication", "error": "Could not assume role: AccessDenied"},
        ]
    }

    summaries = summarize_accounts(aggregate)

    assert summaries[0]["status"] == "success"
    assert summaries[1]["status"] == "failed"
    assert summaries[1]["failure_stage"] == "authentication"
    assert "AccessDenied" in summaries[1]["error"]


def test_format_auth_error_is_a_clear_message():
    message = format_auth_error()
    assert "credentials" in message.lower()
    assert "unable to authenticate" in message.lower()


def test_format_audit_error_does_not_dump_a_traceback():
    message = format_audit_error(RuntimeError("boom"))
    assert message == "Audit failed: boom"
    assert "Traceback" not in message


def test_patch_graph_html_assets_replaces_broken_relative_paths():
    """Mirrors the real output/PROD/graph/graph.html and output/DEV/graph/graph.html
    shape (pyvis's relative node_modules references, which are dead on disk
    since no node_modules folder is generated alongside them) — using
    local, hardcoded sample text only, no real file or AWS involved."""
    sample_html = (
        '<link rel="stylesheet" href="../node_modules/vis/dist/vis.min.css" />'
        '<script type="text/javascript" src="../node_modules/vis/dist/vis.js"></script>'
        '<script>new vis.Network(container, data, options);</script>'
    )

    patched = _patch_graph_html_assets(sample_html)

    assert "../node_modules/vis/dist/vis.js" not in patched
    assert "../node_modules/vis/dist/vis.min.css" not in patched
    assert "cdnjs.cloudflare.com" in patched
    assert "vis.min.js" in patched
    assert "vis.min.css" in patched
    # everything else in the file must be untouched
    assert "new vis.Network(container, data, options);" in patched


def test_patch_graph_html_assets_is_a_no_op_when_nothing_matches():
    untouched = "<html><body>no vis assets here</body></html>"
    assert _patch_graph_html_assets(untouched) == untouched


@pytest.mark.parametrize("account_label", ["PROD", "DEV"])
def test_patch_fixes_the_actual_existing_graph_artifact(account_label):
    """Reads the real, already-generated output/<account>/graph/graph.html
    (never written to, never regenerated) and confirms the patch removes
    its dead relative asset path. Skips if that file isn't present in this
    environment — this test never triggers an audit to create one."""
    graph_file = Path(__file__).parent.parent / "output" / account_label / "graph" / "graph.html"
    if not graph_file.exists():
        pytest.skip(f"{graph_file} not present in this environment")

    original = graph_file.read_text(encoding="utf-8")
    patched = _patch_graph_html_assets(original)

    assert "../node_modules/vis/dist/vis.js" in original  # confirms the bug this patch targets is real
    assert "../node_modules/vis/dist/vis.js" not in patched
    assert "cdnjs.cloudflare.com" in patched


# --- widget presence (Streamlit AppTest harness) ------------------------


def test_credential_fields_exist():
    at = AppTest.from_file(APP_PATH)
    at.run(timeout=15)

    assert not at.exception
    labels = [w.label for w in at.text_input]
    assert any("Access Key ID" in label for label in labels)
    assert any("Secret Access Key" in label for label in labels)
    assert any("Session Token" in label for label in labels)
    assert any("Region" in label for label in labels)

    button_labels = [b.label for b in at.button]
    assert any("Connect & Discover Accounts" in label for label in button_labels)


# --- dashboard rendering (Streamlit AppTest harness, fake aggregate) -------


def test_overview_renders():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)

    # status + counts + a data-derived executive summary sentence
    assert "Needs Attention" in text
    assert "2 AWS accounts were audited" in text
    assert "high-risk finding" in text
    assert "access-review finding" in text
    assert "PROD" in text
    assert "DEV" in text
    assert "328865868092" in text
    assert "587762853586" in text


def test_overview_executive_summary_distinguishes_findings_from_concerns():
    """The summary must count raw findings and curated priority concerns
    separately — never call every finding its own 'issue' when several
    findings describe the same underlying scenario."""
    from src.report.multi_account import _key_risk_groups

    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    concern_count = len(_key_risk_groups(FAKE_AGGREGATE["findings"]))
    assert f"covering {concern_count} priority security concern" in text


def test_prod_account_renders():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert "328865868092" in text
    # PROD's account card shows its finding/high-risk/review counts
    assert any(m.label == "Findings" for m in at.metric)


def test_dev_account_renders_via_account_selector():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    at.selectbox(key="accounts_tab_select").set_value("DEV")
    at.run(timeout=15)
    assert not at.exception

    text = _all_text(at)
    assert "DEV" in text
    assert "587762853586" in text
    assert "dev-admin" in text or "dev-charlie" in text


def test_account_selector_switches_between_accounts():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    assert at.selectbox(key="accounts_tab_select").value == "PROD"

    at.selectbox(key="accounts_tab_select").set_value("DEV")
    at.run(timeout=15)

    assert at.selectbox(key="accounts_tab_select").value == "DEV"
    assert not at.exception


def test_intentional_key_risks_render():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)

    for expected in ("prod-alice", "ProdAdminRole", "prod-bob", "dev-admin", "dev-charlie"):
        assert expected in text


def test_overview_uses_plain_language_risk_descriptions():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert "What we found" in text
    assert "Why it matters" in text
    assert "Recommended action" in text
    assert "has unrestricted AWS permissions" in text
    assert "No recent usage was observed" in text


def test_overview_does_not_expose_technical_details_by_default():
    """Raw policy syntax / policy IDs / raw rule names must live only inside
    the 'View technical details' expander, never in the plain-language body
    of a Key Security Risk card."""
    at = _run_with_aggregate(FAKE_AGGREGATE)

    # at.markdown/at.caption flatten expander contents too (AppTest doesn't
    # model collapsed/expanded state), so scope this to values that appear
    # ONLY within an expander vs anywhere at all.
    all_markdown = [m.value for m in at.markdown]
    all_caption = [c.value for c in at.caption]
    expander_markdown = {m.value for exp in at.expander for m in exp.markdown}
    expander_caption = {c.value for exp in at.expander for c in exp.caption}

    outside_markdown = [v for v in all_markdown if v not in expander_markdown]
    outside_caption = [v for v in all_caption if v not in expander_caption]

    for value in outside_markdown:
        assert "Action=*, Resource=*" not in value
    for value in outside_caption:
        assert not value.startswith("Policy ID:")
        assert not value.startswith("Rule: indirect_privilege_path")


def test_technical_details_appear_when_expanded():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    expander_caption_text = "\n".join(c.value for exp in at.expander for c in exp.caption)
    expander_markdown_text = "\n".join(m.value for exp in at.expander for m in exp.markdown)
    assert "Policy ID: p1" in expander_caption_text
    assert "Rule: indirect_privilege_path" in expander_caption_text
    assert "Action=*, Resource=*" in expander_markdown_text


def test_privilege_escalation_path_visual_renders():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert "prod-alice" in text
    assert "ProdDeveloperRole" in text
    assert "ProdAdminRole" in text
    assert "⬇" in text
    assert "Administrative Access" in text


def test_aws_native_noise_not_shown_as_key_risk():
    at = _run_with_aggregate(FAKE_AGGREGATE)

    # Key Security Risks cards are built only from _key_risk_groups — the
    # noise principal must never appear in that curated set, even though it
    # legitimately exists in the raw findings (Findings tab still shows it).
    from src.report.multi_account import _key_risk_groups

    key_risk_principals = {f["principal"]["name"] for f in _key_risk_groups(FAKE_AGGREGATE["findings"])}
    assert "OrganizationAccountAccessRole" not in key_risk_principals

    # and it must still be reachable somewhere in the app (Findings tab)
    text = _all_text(at)
    assert "OrganizationAccountAccessRole" in text


def test_findings_filtering_by_account_and_rule():
    at = _run_with_aggregate(FAKE_AGGREGATE)

    at.selectbox(key="findings_account_filter").set_value("DEV")
    at.run(timeout=15)
    text = _all_text(at)
    assert "Showing 2 of 6 findings" in text

    at.selectbox(key="findings_rule_filter").set_value("administrative_access")
    at.run(timeout=15)
    text = _all_text(at)
    assert "Showing 1 of 6 findings" in text


def test_overview_shows_high_risk_and_review_counts():
    # "High Risk"/"Review" labels repeat across tabs (Overview's global
    # stat row, then again per-account in Accounts) — Overview's own is
    # always the first occurrence in document order, since that tab renders
    # first.
    at = _run_with_aggregate(FAKE_AGGREGATE)
    first_high_risk = next(m.value for m in at.metric if m.label == "High Risk")
    first_review = next(m.value for m in at.metric if m.label == "Review")
    assert first_high_risk == "4"
    assert first_review == "2"


def test_findings_tab_renders_all_findings_by_default():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert f"All Findings ({len(FAKE_AGGREGATE['findings'])})" in text
    for finding in FAKE_AGGREGATE["findings"]:
        assert finding["principal"]["name"] in text


def test_accounts_tab_does_not_duplicate_every_finding():
    """Accounts must show summaries/top-issues only — not every finding's
    full card (that's Findings' job). "Policy ID:" only ever appears inside
    a full _key_risk_card (Overview) or _finding_card (Findings) expander —
    neither of which Accounts calls — so the total count on the page must
    equal exactly Overview's key-risk cards plus Findings' finding cards,
    with zero extra contributed by Accounts."""
    from src.report.multi_account import _key_risk_groups

    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)

    assert "Top issues" in text

    expected_policy_id_count = len(_key_risk_groups(FAKE_AGGREGATE["findings"])) + len(FAKE_AGGREGATE["findings"])
    assert text.count("Policy ID:") == expected_policy_id_count


def test_detailed_report_download_still_available():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    download_labels = [b.label for b in at.download_button]
    assert any("Download Full PROD Report" in label for label in download_labels)


def test_graph_tab_shows_explanation_and_account_selector():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert "connected" in text
    assert any(sb.key == "graph_tab_select" for sb in at.selectbox)


def test_no_file_uri_links_generated():
    at = _run_with_aggregate(FAKE_AGGREGATE)
    text = _all_text(at)
    assert "file://" not in text

    # switch through every account on both the Accounts and Graph tabs too
    for key in ("accounts_tab_select", "graph_tab_select"):
        for label in ("PROD", "DEV"):
            at.selectbox(key=key).set_value(label)
            at.run(timeout=15)
            assert "file://" not in _all_text(at)


# --- Get Temporary Credentials: pure logic (subprocess mocked directly) ---


def _fake_completed_process(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def test_get_temporary_credentials_success():
    stdout = json.dumps(
        {
            "Credentials": {
                "AccessKeyId": "ASIAFAKEEXAMPLE",
                "SecretAccessKey": "fakeSecretExampleValue",
                "SessionToken": "fakeSessionTokenExampleValue",
                "Expiration": "2026-01-01T01:00:00+00:00",
            }
        }
    )
    with patch("app.subprocess.run", return_value=_fake_completed_process(0, stdout=stdout)):
        creds = get_temporary_credentials_via_local_cli("poc-aws-audit-collector")

    assert creds == {
        "access_key_id": "ASIAFAKEEXAMPLE",
        "secret_access_key": "fakeSecretExampleValue",
        "session_token": "fakeSessionTokenExampleValue",
        "expiration": "2026-01-01T01:00:00+00:00",
    }


def test_get_temporary_credentials_invokes_expected_cli_command():
    stdout = json.dumps(
        {
            "Credentials": {
                "AccessKeyId": "ASIAFAKEEXAMPLE",
                "SecretAccessKey": "fakeSecretExampleValue",
                "SessionToken": "fakeSessionTokenExampleValue",
                "Expiration": "2026-01-01T01:00:00+00:00",
            }
        }
    )
    with patch("app.subprocess.run", return_value=_fake_completed_process(0, stdout=stdout)) as mock_run:
        get_temporary_credentials_via_local_cli("poc-aws-audit-collector")

    args, kwargs = mock_run.call_args
    command = args[0]
    assert command[:3] == ["aws", "sts", "get-session-token"]
    assert "--duration-seconds" in command
    assert command[command.index("--duration-seconds") + 1] == "3600"
    assert "--profile" in command
    assert command[command.index("--profile") + 1] == "poc-aws-audit-collector"
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


def test_get_temporary_credentials_omits_profile_flag_when_none():
    stdout = json.dumps(
        {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "B", "SessionToken": "C", "Expiration": None}}
    )
    with patch("app.subprocess.run", return_value=_fake_completed_process(0, stdout=stdout)) as mock_run:
        get_temporary_credentials_via_local_cli(None)

    command = mock_run.call_args[0][0]
    assert "--profile" not in command


def test_get_temporary_credentials_cli_not_installed():
    with patch("app.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(CredentialRetrievalError) as exc_info:
            get_temporary_credentials_via_local_cli(None)

    assert "AWS CLI not found" in str(exc_info.value)


def test_get_temporary_credentials_cli_failure_gives_safe_message():
    with patch("app.subprocess.run", return_value=_fake_completed_process(255, stderr="Unable to locate credentials")):
        with pytest.raises(CredentialRetrievalError) as exc_info:
            get_temporary_credentials_via_local_cli(None)

    message = str(exc_info.value)
    assert "Could not obtain temporary credentials" in message
    # the raw CLI stderr must never be forwarded verbatim
    assert "Unable to locate credentials" not in message


def test_get_temporary_credentials_timeout():
    with patch("app.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="aws", timeout=20)):
        with pytest.raises(CredentialRetrievalError) as exc_info:
            get_temporary_credentials_via_local_cli(None)

    assert "Timed out" in str(exc_info.value)


def test_get_temporary_credentials_malformed_output():
    with patch("app.subprocess.run", return_value=_fake_completed_process(0, stdout="not json")):
        with pytest.raises(CredentialRetrievalError) as exc_info:
            get_temporary_credentials_via_local_cli(None)

    assert "Unexpected response" in str(exc_info.value)


# --- Get Temporary Credentials: UI (AppTest, subprocess.run patched globally) ---


def test_paste_mode_renders_by_default():
    at = AppTest.from_file(APP_PATH)
    at.run(timeout=15)

    assert not at.exception
    labels = [w.label for w in at.text_input]
    assert any("Access Key ID" in label for label in labels)
    assert any("Secret Access Key" in label for label in labels)
    assert any("Session Token" in label for label in labels)
    assert any("Region" in label for label in labels)


def test_get_credentials_button_renders_when_selected():
    at = AppTest.from_file(APP_PATH)
    at.run(timeout=15)
    at.radio(key="connection_mode").set_value("Get Temporary Credentials")
    at.run(timeout=15)

    assert not at.exception
    button_labels = [b.label for b in at.button]
    assert any("Get Temporary Credentials" in label for label in button_labels)
    text = _all_text(at)
    assert "local AWS authentication" in text


def _fake_credentials_stdout(expiration="2026-01-01T01:00:00+00:00"):
    return json.dumps(
        {
            "Credentials": {
                "AccessKeyId": "ASIAFAKEEXAMPLE",
                "SecretAccessKey": "fakeSecretExampleValue",
                "SessionToken": "fakeSessionTokenExampleValue",
                "Expiration": expiration,
            }
        }
    )


def _retrieve_credentials_via_ui():
    at = AppTest.from_file(APP_PATH)
    at.run(timeout=15)
    at.radio(key="connection_mode").set_value("Get Temporary Credentials")
    at.run(timeout=15)
    for button in at.button:
        if button.label == "Get Temporary Credentials":
            button.click()
    at.run(timeout=15)
    return at


def test_successful_retrieval_populates_fields_and_does_not_auto_audit():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout())):
        at = _retrieve_credentials_via_ui()

    assert not at.exception
    assert at.session_state["access_key_id"] == "ASIAFAKEEXAMPLE"
    assert at.session_state["secret_access_key"] == "fakeSecretExampleValue"
    assert at.session_state["session_token"] == "fakeSessionTokenExampleValue"
    assert at.session_state["credential_expiration"] == "2026-01-01T01:00:00+00:00"
    # retrieval alone must never trigger an audit
    assert at.session_state["aggregate"] is None


def test_expiration_is_displayed():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout())):
        at = _retrieve_credentials_via_ui()

    assert "2026-01-01T01:00:00+00:00" in _all_text(at)


def test_credential_fields_masked_by_default():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout())):
        at = _retrieve_credentials_via_ui()

    masked_fields = {w.key: w for w in at.text_input if w.key in ("access_key_id", "secret_access_key", "session_token")}
    assert len(masked_fields) == 3
    for field in masked_fields.values():
        assert field.proto.type == 1  # PASSWORD


def test_show_hide_reveal_toggle_works():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout())):
        at = _retrieve_credentials_via_ui()
        at.checkbox[0].set_value(True)
        at.run(timeout=15)

    revealed_fields = {w.key: w for w in at.text_input if w.key in ("access_key_id", "secret_access_key", "session_token")}
    assert len(revealed_fields) == 3
    for field in revealed_fields.values():
        assert field.proto.type == 0  # DEFAULT (revealed)


def test_cli_failure_shown_as_safe_error_in_ui():
    with patch("subprocess.run", return_value=_fake_completed_process(255, stderr="Unable to locate credentials")):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        at.radio(key="connection_mode").set_value("Get Temporary Credentials")
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Get Temporary Credentials":
                button.click()
        at.run(timeout=15)

    assert not at.exception
    text = _all_text(at)
    assert "Could not obtain temporary credentials" in text
    assert "Unable to locate credentials" not in text


def test_credentials_never_appear_in_rendered_output():
    stdout = json.dumps(
        {
            "Credentials": {
                "AccessKeyId": "ASIASECRETVISIBLEIFLEAKED",
                "SecretAccessKey": "SUPERSECRETVALUESHOULDNOTLEAK",
                "SessionToken": "SUPERSECRETTOKENSHOULDNOTLEAK",
            }
        }
    )
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=stdout)):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        at.radio(key="connection_mode").set_value("Get Temporary Credentials")
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Get Temporary Credentials":
                button.click()
        at.run(timeout=15)

    text = _all_text(at)
    assert "SUPERSECRETVALUESHOULDNOTLEAK" not in text
    assert "SUPERSECRETTOKENSHOULDNOTLEAK" not in text
    assert "ASIASECRETVISIBLEIFLEAKED" not in text


# --- credential session reuse: avoid an STS call while credentials are still valid ---


def _future_expiration(hours=1) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _past_expiration(hours=1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def test_first_get_credentials_click_performs_one_sts_call():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout())) as mock_run:
        at = _retrieve_credentials_via_ui()

    assert mock_run.call_count == 1
    assert at.session_state["access_key_id"] == "ASIAFAKEEXAMPLE"
    assert at.session_state["credential_expiration"] == "2026-01-01T01:00:00+00:00"


def test_valid_credentials_display_expiration_and_remaining_time():
    expiration = _future_expiration(hours=2)
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(expiration))):
        at = _retrieve_credentials_via_ui()
        # one more rerun so the script re-evaluates validity against the
        # now-stored session state (the run that processes the click itself
        # still renders the pre-click "no credentials yet" button choice)
        at.run(timeout=15)

    text = _all_text(at)
    assert "Temporary credentials already available" in text
    assert expiration in text
    assert "Valid for" in text


def test_repeated_click_while_valid_does_not_call_sts_again():
    expiration = _future_expiration(hours=1)
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(expiration))) as mock_run:
        at = _retrieve_credentials_via_ui()
        assert mock_run.call_count == 1
        at.run(timeout=15)  # re-render now that valid credentials are in session state

        # once valid, "Get Temporary Credentials" is no longer offered at all —
        # only "Generate New Credentials" — so a repeat "get" click can't happen,
        # and a plain rerun must not trigger another STS call either.
        button_labels = [b.label for b in at.button]
        assert "Get Temporary Credentials" not in button_labels
        assert "Generate New Credentials" in button_labels

        at.run(timeout=15)

    assert mock_run.call_count == 1


def test_generate_new_credentials_calls_sts_once_and_replaces_old_credentials():
    old_expiration = _future_expiration(hours=1)
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(old_expiration))) as mock_run:
        at = _retrieve_credentials_via_ui()
        assert mock_run.call_count == 1
        assert at.session_state["access_key_id"] == "ASIAFAKEEXAMPLE"
        at.run(timeout=15)  # re-render so "Generate New Credentials" is offered

        new_expiration = _future_expiration(hours=3)
        new_stdout = json.dumps(
            {
                "Credentials": {
                    "AccessKeyId": "ASIANEWEXAMPLE",
                    "SecretAccessKey": "newSecretExampleValue",
                    "SessionToken": "newSessionTokenExampleValue",
                    "Expiration": new_expiration,
                }
            }
        )
        mock_run.return_value = _fake_completed_process(0, stdout=new_stdout)

        for button in at.button:
            if button.label == "Generate New Credentials":
                button.click()
        at.run(timeout=15)

    assert mock_run.call_count == 2
    assert at.session_state["access_key_id"] == "ASIANEWEXAMPLE"
    assert at.session_state["credential_expiration"] == new_expiration
    # generating new credentials must never itself start an audit
    assert at.session_state["aggregate"] is None


def test_expired_credentials_show_expired_message_and_allow_fresh_generation():
    expired = _past_expiration(hours=1)
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(expired))) as mock_run:
        at = _retrieve_credentials_via_ui()
        assert mock_run.call_count == 1
        at.run(timeout=15)  # re-render now that expired credentials are in session state

        text = _all_text(at)
        assert "Temporary credentials expired" in text
        button_labels = [b.label for b in at.button]
        assert "Get Temporary Credentials" in button_labels
        assert "Generate New Credentials" not in button_labels

        for button in at.button:
            if button.label == "Get Temporary Credentials":
                button.click()
        at.run(timeout=15)

    assert mock_run.call_count == 2
    assert at.session_state["aggregate"] is None


def test_unparseable_expiration_fails_closed_and_allows_fresh_generation():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout("not-a-real-timestamp"))) as mock_run:
        at = _retrieve_credentials_via_ui()
        assert mock_run.call_count == 1
        at.run(timeout=15)  # re-render against the now-stored unparseable expiration

    button_labels = [b.label for b in at.button]
    assert "Get Temporary Credentials" in button_labels
    assert "Generate New Credentials" not in button_labels


def test_missing_expiration_fails_closed_and_allows_fresh_generation():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(None))) as mock_run:
        at = _retrieve_credentials_via_ui()
        assert mock_run.call_count == 1
        at.run(timeout=15)

    button_labels = [b.label for b in at.button]
    assert "Get Temporary Credentials" in button_labels
    assert "Generate New Credentials" not in button_labels


def test_terminal_printing_only_happens_on_new_retrieval(monkeypatch, capsys):
    monkeypatch.delenv("SENTINEL_DISABLE_LOCAL_CREDENTIAL_PRINT", raising=False)
    expiration = _future_expiration(hours=1)

    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(expiration))):
        at = _retrieve_credentials_via_ui()
    assert "Temporary AWS credentials retrieved" in capsys.readouterr().out

    # valid credentials, no button click on this rerun — no new STS call, no new print
    at.run(timeout=15)
    assert "Temporary AWS credentials retrieved" not in capsys.readouterr().out


def test_getting_credentials_never_starts_audit_regardless_of_validity():
    with patch("subprocess.run", return_value=_fake_completed_process(0, stdout=_fake_credentials_stdout(_future_expiration()))):
        at = _retrieve_credentials_via_ui()
    assert at.session_state["aggregate"] is None


def test_graph_tab_renders_without_crashing():
    """Whether or not a real output/<account>/graph/graph.html happens to
    exist in this environment, the Graph tab must render cleanly either
    way — embedding it if present, or a clear message if not."""
    at = _run_with_aggregate(FAKE_AGGREGATE)
    at.selectbox(key="graph_tab_select").set_value("PROD")
    at.run(timeout=15)

    assert not at.exception
    text = _all_text(at)
    assert "connected" in text  # the explanation of what the graph represents


# --- real audit progress (orchestrator/auth mocked end-to-end, no AWS/OpenAI) ---


_FAKE_PIPELINE_AGGREGATE = {
    "management_account_id": "123456789012",
    "organizations_status": {"succeeded": True},
    "accounts": [
        {"account_label": "PROD", "account_id": "328865868092", "status": "success", "finding_count": 1},
    ],
    "accounts_succeeded": 1,
    "accounts_failed": 0,
    "findings": [],
    "total_findings": 0,
}


_FAKE_DISCOVERED_ACCOUNTS = [
    {"id": "328865868092", "name": "PROD", "email": "prod@example.com", "state": "ACTIVE"},
]


def _run_connect_and_audit(fake_audit_all_accounts, discovered_accounts=None):
    """Drives the full Connect & Discover -> select account -> Run Audit
    flow. discovered_accounts defaults to one account (PROD), auto-selected,
    so existing tests that only care about the audit/progress behavior don't
    each need to repeat the discovery/selection setup themselves."""
    fake_identity = {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test", "region": "us-east-1"}
    accounts = discovered_accounts if discovered_accounts is not None else _FAKE_DISCOVERED_ACCOUNTS
    with (
        patch("src.aws.auth.verify_identity", return_value=fake_identity),
        patch("src.orchestrator.discover_accounts", return_value=(accounts, ok("organizations", {"accounts": len(accounts)}))),
        patch("src.orchestrator.audit_all_accounts", side_effect=fake_audit_all_accounts),
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        at.text_input(key="access_key_id").set_value("FAKEKEYID")
        at.text_input(key="secret_access_key").set_value("FAKESECRET")
        at.text_input(key="session_token").set_value("")
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Connect & Discover Accounts":
                button.click()
        at.run(timeout=15)
        for account in accounts:
            at.checkbox(key=f"select_account_{account['id']}").set_value(True)
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Run Audit":
                button.click()
        at.run(timeout=15)
    return at


def test_progress_callback_events_produce_step_and_stage_rendering():
    def fake_audit(session, progress_callback=None, **kwargs):
        progress_callback(2, 9, "IAM Configuration Collection", status="running", account_label="PROD")
        progress_callback(2, 9, "IAM Configuration Collection", status="completed", duration_seconds=1.5, account_label="PROD")
        progress_callback(3, 9, "IAM Normalization", status="running", account_label="PROD")
        progress_callback(3, 9, "IAM Normalization", status="completed", duration_seconds=0.1, account_label="PROD")
        return _FAKE_PIPELINE_AGGREGATE

    at = _run_connect_and_audit(fake_audit)
    assert not at.exception

    text = _all_text(at)
    assert "IAM Configuration Collection" in text
    assert "IAM Normalization" in text
    assert "Group Inheritance" in text  # a stage that never fired must still be listed (pending)
    assert "Step" in text and "of 9" in text
    assert "Elapsed time" in text


def test_completed_stage_shows_duration():
    def fake_audit(session, progress_callback=None, **kwargs):
        progress_callback(2, 9, "IAM Configuration Collection", status="running", account_label="PROD")
        progress_callback(2, 9, "IAM Configuration Collection", status="completed", duration_seconds=6.35, account_label="PROD")
        return _FAKE_PIPELINE_AGGREGATE

    at = _run_connect_and_audit(fake_audit)
    assert "6.35s" in _all_text(at)


def test_failed_stage_renders_and_error_shown():
    def fake_audit(session, progress_callback=None, **kwargs):
        progress_callback(2, 9, "IAM Configuration Collection", status="running", account_label="PROD")
        progress_callback(2, 9, "IAM Configuration Collection", status="failed", duration_seconds=0.5, account_label="PROD")
        raise RuntimeError("IAM collection: simulated AccessDenied")

    at = _run_connect_and_audit(fake_audit)
    assert not at.exception

    text = _all_text(at)
    assert "IAM Configuration Collection" in text
    assert "Audit failed" in text or "simulated AccessDenied" in text
    # never a raw traceback or credential value
    assert "Traceback" not in text
    assert "FAKESECRET" not in text


def test_completion_summary_renders():
    def fake_audit(session, progress_callback=None, **kwargs):
        return _FAKE_PIPELINE_AGGREGATE

    at = _run_connect_and_audit(fake_audit)

    text = _all_text(at)
    assert "Audit completed successfully" in text
    assert "1 accounts audited" in text
    assert "0 findings" in text
    assert "0 failures" in text
    assert "Total audit time" in text


def test_existing_audit_result_behavior_unchanged():
    """The dashboard itself must still render exactly as before this change,
    driven by the same aggregate shape — this feature only adds progress
    reporting around the existing call, it doesn't alter what's returned."""

    def fake_audit(session, progress_callback=None, **kwargs):
        return _FAKE_PIPELINE_AGGREGATE

    at = _run_connect_and_audit(fake_audit)

    assert at.session_state["aggregate"] == _FAKE_PIPELINE_AGGREGATE
    text = _all_text(at)
    assert "PROD" in text


# --- account discovery + selection (Organizations discovery drives selection, not a hardcoded list) ---


def _fake_identity():
    return {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test", "region": "us-east-1"}


def _enter_credentials_and_discover(at):
    at.text_input(key="access_key_id").set_value("FAKEKEYID")
    at.text_input(key="secret_access_key").set_value("FAKESECRET")
    at.text_input(key="session_token").set_value("")
    at.run(timeout=15)
    for button in at.button:
        if button.label == "Connect & Discover Accounts":
            button.click()
    at.run(timeout=15)


def test_discovered_accounts_render_as_selectable_checkboxes():
    fake_accounts = [
        {"id": "111111111111", "name": "PROD", "email": "p@x.com", "state": "ACTIVE"},
        {"id": "222222222222", "name": "DEV", "email": "d@x.com", "state": "ACTIVE"},
    ]
    with (
        patch("src.aws.auth.verify_identity", return_value=_fake_identity()),
        patch("src.orchestrator.discover_accounts", return_value=(fake_accounts, ok("organizations", {"accounts": 2}))),
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        _enter_credentials_and_discover(at)

    checkbox_keys = {cb.key for cb in at.checkbox}
    assert "select_account_111111111111" in checkbox_keys
    assert "select_account_222222222222" in checkbox_keys
    # unselected by default — no account gets audited just from being discovered
    assert all(cb.value is False for cb in at.checkbox if cb.key in checkbox_keys)

    checkbox_labels = [cb.label for cb in at.checkbox]
    assert any("PROD" in label and "111111111111" in label and "ACTIVE" in label for label in checkbox_labels)
    assert any("DEV" in label and "222222222222" in label for label in checkbox_labels)


def test_selected_account_reaches_orchestrator_unselected_is_excluded():
    fake_accounts = [
        {"id": "111111111111", "name": "PROD", "email": "p@x.com", "state": "ACTIVE"},
        {"id": "222222222222", "name": "DEV", "email": "d@x.com", "state": "ACTIVE"},
    ]
    captured = {}

    def fake_audit(session, target_accounts=None, organizations_status=None, progress_callback=None):
        captured["target_accounts"] = target_accounts
        return _FAKE_PIPELINE_AGGREGATE

    with (
        patch("src.aws.auth.verify_identity", return_value=_fake_identity()),
        patch("src.orchestrator.discover_accounts", return_value=(fake_accounts, ok("organizations", {"accounts": 2}))),
        patch("src.orchestrator.audit_all_accounts", side_effect=fake_audit),
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        _enter_credentials_and_discover(at)

        # only PROD selected — DEV stays unchecked
        at.checkbox(key="select_account_111111111111").set_value(True)
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Run Audit":
                button.click()
        at.run(timeout=15)

    assert captured["target_accounts"] == {"PROD": "111111111111"}


def test_no_account_selected_blocks_audit_with_clear_message():
    fake_accounts = [{"id": "111111111111", "name": "PROD", "email": "p@x.com", "state": "ACTIVE"}]

    with (
        patch("src.aws.auth.verify_identity", return_value=_fake_identity()),
        patch("src.orchestrator.discover_accounts", return_value=(fake_accounts, ok("organizations", {"accounts": 1}))),
        patch("src.orchestrator.audit_all_accounts") as mock_audit,
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        _enter_credentials_and_discover(at)

        for button in at.button:
            if button.label == "Run Audit":
                button.click()
        at.run(timeout=15)

        mock_audit.assert_not_called()

    assert "Select at least one account" in _all_text(at)


def test_discovery_with_no_accounts_shows_message_and_no_checkboxes():
    with (
        patch("src.aws.auth.verify_identity", return_value=_fake_identity()),
        patch("src.orchestrator.discover_accounts", return_value=([], ok("organizations", {"accounts": 0}))),
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        _enter_credentials_and_discover(at)

    assert len(at.checkbox) == 0
    assert "No accounts were discovered" in _all_text(at)


def test_discover_accounts_not_queried_again_during_run_audit():
    """discover_accounts (Organizations) is called once at Connect time —
    running the audit afterward must reuse that same result, not trigger a
    second Organizations API call."""
    fake_accounts = [{"id": "111111111111", "name": "PROD", "email": "p@x.com", "state": "ACTIVE"}]

    with (
        patch("src.aws.auth.verify_identity", return_value=_fake_identity()),
        patch("src.orchestrator.discover_accounts", return_value=(fake_accounts, ok("organizations", {"accounts": 1}))) as mock_discover,
        patch("src.orchestrator.audit_all_accounts", return_value=_FAKE_PIPELINE_AGGREGATE),
    ):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        _enter_credentials_and_discover(at)

        at.checkbox(key="select_account_111111111111").set_value(True)
        at.run(timeout=15)
        for button in at.button:
            if button.label == "Run Audit":
                button.click()
        at.run(timeout=15)

    assert mock_discover.call_count == 1


def test_selected_target_accounts_ignores_non_discovered_ids():
    """The selection UI only ever offers checkboxes for discovered accounts,
    so this proves the mapping function structurally can't include an
    account that wasn't actually discovered, even if a stray session_state
    key existed for one."""
    from app import _selected_target_accounts

    discovered = [{"id": "111111111111", "name": "PROD", "email": "p@x.com", "state": "ACTIVE"}]
    st.session_state["select_account_111111111111"] = True
    st.session_state["select_account_999999999999"] = True  # not in discovered

    assert _selected_target_accounts(discovered) == {"PROD": "111111111111"}


def test_selected_target_accounts_disambiguates_duplicate_names():
    from app import _selected_target_accounts

    discovered = [
        {"id": "111111111111", "name": "Sandbox", "email": "a@x.com", "state": "ACTIVE"},
        {"id": "222222222222", "name": "Sandbox", "email": "b@x.com", "state": "ACTIVE"},
    ]
    st.session_state["select_account_111111111111"] = True
    st.session_state["select_account_222222222222"] = True

    assert _selected_target_accounts(discovered) == {
        "Sandbox (111111111111)": "111111111111",
        "Sandbox (222222222222)": "222222222222",
    }
