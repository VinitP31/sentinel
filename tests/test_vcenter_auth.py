"""vCenter Phase 1 authentication tests.

Fully mocked - no network call, no real vCenter contact, nothing destructive.
Covers only: missing credentials, and REST/SOAP authentication failures
being wrapped cleanly without ever exposing the password.
"""

from unittest.mock import patch

import pytest
import requests

from src.vcenter import auth


def test_missing_credentials_raises_cleanly(monkeypatch):
    monkeypatch.delenv("VCENTER_HOST", raising=False)
    monkeypatch.delenv("VCENTER_USERNAME", raising=False)
    monkeypatch.delenv("VCENTER_PASSWORD", raising=False)

    with pytest.raises(auth.VCenterAuthError):
        auth.rest_login()


def test_rest_login_failure_does_not_leak_password(monkeypatch):
    monkeypatch.setenv("VCENTER_HOST", "vcenter.example.test")
    monkeypatch.setenv("VCENTER_USERNAME", "administrator@vsphere.local")
    monkeypatch.setenv("VCENTER_PASSWORD", "super-secret-value")

    with patch.object(auth.requests, "post", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(auth.VCenterAuthError) as exc_info:
            auth.rest_login()

    assert "super-secret-value" not in str(exc_info.value)


def test_rest_login_normalizes_host_to_base_url(monkeypatch):
    monkeypatch.setenv("VCENTER_HOST", "https://vcenter.example.test/ui/app/home")
    monkeypatch.setenv("VCENTER_USERNAME", "administrator@vsphere.local")
    monkeypatch.setenv("VCENTER_PASSWORD", "irrelevant")

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return "fake-session-id"

    with patch.object(auth.requests, "post", return_value=_FakeResponse()) as mock_post:
        base_url, session_id = auth.rest_login()

    assert base_url == "https://vcenter.example.test"
    assert session_id == "fake-session-id"
    called_url = mock_post.call_args[0][0]
    assert called_url == "https://vcenter.example.test/api/session"


def test_soap_login_failure_does_not_leak_password(monkeypatch):
    monkeypatch.setenv("VCENTER_HOST", "vcenter.example.test")
    monkeypatch.setenv("VCENTER_USERNAME", "administrator@vsphere.local")
    monkeypatch.setenv("VCENTER_PASSWORD", "super-secret-value")

    with patch.object(auth, "SmartConnect", side_effect=Exception("invalid login")):
        with pytest.raises(auth.VCenterAuthError) as exc_info:
            auth.soap_login()

    assert "super-secret-value" not in str(exc_info.value)


def test_verify_rest_session_failure_wrapped_cleanly():
    with patch.object(auth.requests, "get", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(auth.VCenterAuthError):
            auth.verify_rest_session("https://vcenter.example.test", "fake-session-id")


def test_verify_soap_session_failure_wrapped_cleanly():
    class _FailingServiceInstance:
        def CurrentTime(self):
            raise Exception("session expired")

    with pytest.raises(auth.VCenterAuthError):
        auth.verify_soap_session(_FailingServiceInstance())
