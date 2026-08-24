"""write_json serialization tests.

Covers the non-JSON-native types collectors/pipeline results actually
produce: datetime (from boto3 responses), Path (from pipeline result dicts,
e.g. findings_path/report_path), and CollectionStatus (from a pipeline
result's statuses list) — write_json must handle all three rather than
raising mid-write.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from src.util.io import write_json
from src.util.status import ok


def test_write_json_serializes_datetime(tmp_path):
    path = write_json(tmp_path / "out.json", {"finished": datetime(2026, 1, 1, tzinfo=timezone.utc)})

    loaded = json.loads(path.read_text())
    assert loaded["finished"] == "2026-01-01T00:00:00+00:00"


def test_write_json_serializes_path(tmp_path):
    nested = {"findings_path": tmp_path / "findings.json", "count": 3}
    path = write_json(tmp_path / "out.json", nested)

    loaded = json.loads(path.read_text())
    assert loaded["findings_path"] == str(tmp_path / "findings.json")
    assert loaded["count"] == 3


def test_write_json_serializes_collection_status(tmp_path):
    status = ok("iam_configuration", {"users": 3})
    path = write_json(tmp_path / "out.json", {"statuses": [status]})

    loaded = json.loads(path.read_text())
    assert loaded["statuses"][0] == status.as_dict()
