"""vCenter inventory collector tests.

Fully mocked REST responses - no network call, no real vCenter contact.
"""

from unittest.mock import Mock

import pytest

from src.vcenter.inventory_collector import collect
from src.vcenter.rest_client import VCenterRestError

FIXTURE_RESPONSES = {
    "/api/vcenter/datacenter": [{"datacenter": "datacenter-1", "name": "DC1"}],
    "/api/vcenter/folder": [
        {"folder": "group-h1", "name": "host", "type": "HOST"},
        {"folder": "group-v1", "name": "vm", "type": "VM"},
    ],
    "/api/vcenter/cluster": [{"cluster": "domain-c1", "name": "Cluster1"}, {"cluster": "domain-c2", "name": "Cluster2"}],
    "/api/vcenter/host": [],
    "/api/vcenter/vm": [],
    "/api/vcenter/resource-pool": [{"resource_pool": "resgroup-1", "name": "Resources"}],
}


def _fake_client(responses: dict[str, list[dict]]) -> Mock:
    client = Mock()
    client.get.side_effect = lambda path: responses[path]
    return client


def test_collect_returns_records_per_object_type():
    client = _fake_client(FIXTURE_RESPONSES)
    inventory, status = collect(client)

    assert status.succeeded
    assert inventory["datacenter"] == [{"id": "datacenter-1", "type": "datacenter", "name": "DC1", "parent": None}]
    assert inventory["cluster"][0]["id"] == "domain-c1"
    assert inventory["cluster"][1]["name"] == "Cluster2"
    assert inventory["resource_pool"] == [{"id": "resgroup-1", "type": "resource_pool", "name": "Resources", "parent": None}]


def test_collect_counts_reflect_record_counts():
    client = _fake_client(FIXTURE_RESPONSES)
    _inventory, status = collect(client)

    assert status.record_counts == {"datacenter": 1, "folder": 2, "cluster": 2, "host": 0, "vm": 0, "resource_pool": 1}


def test_empty_object_type_is_a_normal_success_not_a_failure():
    client = _fake_client(FIXTURE_RESPONSES)
    inventory, status = collect(client)

    assert status.succeeded
    assert inventory["host"] == []
    assert inventory["vm"] == []


def test_parent_field_only_populated_when_actually_present_in_response():
    responses = dict(FIXTURE_RESPONSES)
    responses["/api/vcenter/cluster"] = [{"cluster": "domain-c1", "name": "Cluster1", "parent": "group-h1"}]
    client = _fake_client(responses)

    inventory, _status = collect(client)

    assert inventory["cluster"][0]["parent"] == "group-h1"
    assert inventory["datacenter"][0]["parent"] is None  # not present in that fixture response


def test_rest_failure_is_reported_as_failed_status_not_raised():
    client = Mock()
    client.get.side_effect = VCenterRestError("connection refused")

    inventory, status = collect(client)

    assert inventory == {}
    assert not status.succeeded
    assert "connection refused" in status.error


def test_collect_calls_each_endpoint_exactly_once():
    client = _fake_client(FIXTURE_RESPONSES)
    collect(client)

    called_paths = [call.args[0] for call in client.get.call_args_list]
    assert called_paths == [
        "/api/vcenter/datacenter",
        "/api/vcenter/folder",
        "/api/vcenter/cluster",
        "/api/vcenter/host",
        "/api/vcenter/vm",
        "/api/vcenter/resource-pool",
    ]
