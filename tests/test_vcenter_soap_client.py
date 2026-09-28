"""vCenter SOAP client tests.

Fully mocked ServiceInstance - no network call, no real vCenter contact.
"""

from unittest.mock import Mock

import pytest

from src.vcenter.soap_client import VCenterSoapClient, VCenterSoapError


def test_current_time_returns_string():
    service_instance = Mock()
    service_instance.CurrentTime.return_value = "2026-09-21T12:00:00Z"

    client = VCenterSoapClient(service_instance=service_instance)
    result = client.current_time()

    assert result == "2026-09-21T12:00:00Z"
    service_instance.CurrentTime.assert_called_once()


def test_current_time_wraps_errors():
    service_instance = Mock()
    service_instance.CurrentTime.side_effect = Exception("session expired")

    client = VCenterSoapClient(service_instance=service_instance)

    with pytest.raises(VCenterSoapError):
        client.current_time()


def test_content_fetched_and_cached():
    service_instance = Mock()
    fake_content = object()
    service_instance.RetrieveContent.return_value = fake_content

    client = VCenterSoapClient(service_instance=service_instance)

    assert client.content is fake_content
    assert client.content is fake_content  # second access must not re-fetch
    service_instance.RetrieveContent.assert_called_once()


def test_content_wraps_errors():
    service_instance = Mock()
    service_instance.RetrieveContent.side_effect = Exception("connection lost")

    client = VCenterSoapClient(service_instance=service_instance)

    with pytest.raises(VCenterSoapError):
        client.content


def test_client_has_no_write_methods():
    """Structural check: only the documented read surface exists, no write verb."""
    service_instance = Mock()
    client = VCenterSoapClient(service_instance=service_instance)

    public_attrs = {name for name in dir(client) if not name.startswith("_")}
    assert public_attrs == {"service_instance", "content", "current_time"}

    for verb in ("create", "set", "update", "remove", "delete", "reconfigure", "power_on", "power_off"):
        assert not hasattr(client, verb)
