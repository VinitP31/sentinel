# vCenter inventory collection.
"""vCenter inventory collection.

Reads inventory objects via the vSphere Automation (REST) API - see
src/vcenter/CLAUDE.md section 4 (REST -> inventory/resource context). Each
object type is fetched with exactly one unfiltered GET against its
documented list endpoint. Read-only: every endpoint used here is a List
operation, nothing else.

Parent relationship: the vSphere Automation API's list/summary responses for
these resource types are not documented as including a parent reference.
Each returned record's "parent" field is populated only if the live response
actually contains one - never invented. If it is absent, reconstructing the
full tree needs a separate, filtered traversal, which is out of scope here.
"""

from src.util.status import CollectionStatus, failed, ok
from src.vcenter.rest_client import VCenterRestClient, VCenterRestError

SOURCE = "vcenter_inventory"

# object_type -> (list endpoint, id field name in that endpoint's response)
_ENDPOINTS = {
    "datacenter": ("/api/vcenter/datacenter", "datacenter"),
    "folder": ("/api/vcenter/folder", "folder"),
    "cluster": ("/api/vcenter/cluster", "cluster"),
    "host": ("/api/vcenter/host", "host"),
    "vm": ("/api/vcenter/vm", "vm"),
    "resource_pool": ("/api/vcenter/resource-pool", "resource_pool"),
}


def _record(item: dict, object_type: str, id_field: str) -> dict:
    return {
        "id": item.get(id_field),
        "type": object_type,
        "name": item.get("name"),
        "parent": item.get("parent"),
    }


def collect(client: VCenterRestClient) -> tuple[dict, CollectionStatus]:
    """Fetch datacenters, folders, clusters, hosts, VMs, and resource pools.

    One unfiltered GET per object type - six real calls total. An empty
    list for any type is a normal, successful result, not a failure.
    """
    inventory: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}

    for object_type, (path, id_field) in _ENDPOINTS.items():
        try:
            items = client.get(path)
        except VCenterRestError as exc:
            return {}, failed(SOURCE, f"{object_type} collection failed: {exc}")

        records = [_record(item, object_type, id_field) for item in items]
        inventory[object_type] = records
        counts[object_type] = len(records)

    return inventory, ok(SOURCE, counts)
