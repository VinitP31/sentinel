# vCenter REST API client.
"""Thin, read-only wrapper over the vSphere Automation (REST) API.

Authentication and session lifecycle live in src/vcenter/auth.py - this
module only issues requests against an already-established session (base_url
+ session id from auth.rest_login()). It does not log in, refresh, or log
out a session itself.

Only a GET method exists here, by design: the connector is read-only end to
end, so the REST client that talks to vCenter has no method capable of
writing to it, independent of what path is passed in.
"""

from dataclasses import dataclass

import requests


class VCenterRestError(RuntimeError):
    """A REST call to vCenter failed."""


@dataclass
class VCenterRestClient:
    """Issues read-only GET requests against an already-authenticated REST session."""

    base_url: str
    session_id: str
    timeout: int = 30

    def get(self, path: str) -> dict | list:
        """GET {base_url}{path}, authenticated via vmware-api-session-id.

        path must start with '/'. Returns the parsed JSON body. Raises
        VCenterRestError on any HTTP or network failure.
        """
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        try:
            response = requests.get(
                f"{self.base_url}{path}",
                headers={"vmware-api-session-id": self.session_id},
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise VCenterRestError(f"GET {path} failed: {exc}") from exc
        return response.json()
