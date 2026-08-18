"""Collection status.

A failed collection and an empty result are different states. Conflating them
makes a partial run indistinguishable from a complete one, so every collector
returns one of these alongside its data.
"""

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class CollectionStatus:
    source: str
    succeeded: bool
    record_counts: dict[str, int] = field(default_factory=dict)
    pages_fetched: int = 0
    error: str | None = None
    denied_actions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def ok(source: str, counts: dict[str, int], pages: int = 0) -> CollectionStatus:
    return CollectionStatus(source=source, succeeded=True, record_counts=counts, pages_fetched=pages)


def failed(source: str, error: str) -> CollectionStatus:
    return CollectionStatus(source=source, succeeded=False, error=error)
