"""vCenter REST client tests.

Fully mocked - no network call, no real vCenter contact. Covers only the
generic GET wrapper: success, HTTP/network failure, and path validation.
"""

from unittest.mock import Mock, patch

import pytest
import requests

from src.vcenter.rest_client import VCenterRestClient, VCenterRestError


def test_get_returns_parsed_json():
    client = VCenterRestClient(base_url="https://vcenter.example.test", session_id="fake-session-id")
    fake_response = Mock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"value": "ok"}

    with patch.object(requests, "get", return_value=fake_response) as mock_get:
        result = client.get("/api/session")

    assert result == {"value": "ok"}
    called_url = mock_get.call_args[0][0]
    called_headers = mock_get.call_args[1]["headers"]
    assert called_url == "https://vcenter.example.test/api/session"
    assert called_headers == {"vmware-api-session-id": "fake-session-id"}


def test_get_wraps_http_error():
    client = VCenterRestClient(base_url="https://vcenter.example.test", session_id="fake-session-id")
    fake_response = Mock()
    fake_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")

    with patch.object(requests, "get", return_value=fake_response):
        with pytest.raises(VCenterRestError):
            client.get("/api/session")


def test_get_wraps_connection_error():
    client = VCenterRestClient(base_url="https://vcenter.example.test", session_id="fake-session-id")

    with patch.object(requests, "get", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(VCenterRestError):
            client.get("/api/session")


def test_get_rejects_path_without_leading_slash():
    client = VCenterRestClient(base_url="https://vcenter.example.test", session_id="fake-session-id")

    with pytest.raises(ValueError):
        client.get("api/session")


def test_client_has_no_write_methods():
    """Structural check: no post/put/patch/delete verb exists on the client."""
    client = VCenterRestClient(base_url="https://vcenter.example.test", session_id="fake-session-id")
    for verb in ("post", "put", "patch", "delete"):
        assert not hasattr(client, verb)
