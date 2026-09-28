# vCenter authentication.
"""vCenter Phase 1 authentication.

Establishes REST (vSphere Automation API) and SOAP (pyVmomi, vSphere Web
Services API) sessions as two independent integration points, per
src/vcenter/CLAUDE.md section 5 - the REST session id is never reused as the
SOAP session, and vice versa. Read-only by construction: every function here
either authenticates or reads session metadata; none creates, modifies, or
deletes any vCenter object.

Credentials come only from VCENTER_HOST / VCENTER_USERNAME / VCENTER_PASSWORD
(environment). Never hardcoded, never logged, never included in an exception
message or return value.
"""

import ssl
from dataclasses import dataclass
from os import getenv
from urllib.parse import urlsplit, urlunsplit

import requests
from pyVim.connect import Disconnect, SmartConnect


class VCenterAuthError(RuntimeError):
    """vCenter authentication or session verification failed."""


def _credentials() -> tuple[str, str, str]:
    host = getenv("VCENTER_HOST")
    username = getenv("VCENTER_USERNAME")
    password = getenv("VCENTER_PASSWORD")
    if not host or not username or not password:
        raise VCenterAuthError(
            "VCENTER_HOST, VCENTER_USERNAME and VCENTER_PASSWORD must all be set"
        )
    return host, username, password


def _rest_base_url(host: str) -> str:
    """Normalize VCENTER_HOST to scheme://host, discarding any UI path/query."""
    parts = urlsplit(host if "://" in host else f"https://{host}")
    return urlunsplit((parts.scheme or "https", parts.netloc, "", "", ""))


@dataclass
class VCenterSession:
    """Two independent sessions, held together for convenience only.

    rest_base_url/rest_session_id: vSphere Automation API session.
    soap_service_instance: pyVmomi ServiceInstance from a separate SmartConnect login.
    """

    rest_base_url: str
    rest_session_id: str
    soap_service_instance: object


def rest_login() -> tuple[str, str]:
    """POST {base_url}/api/session - vSphere Automation API session creation.

    HTTP Basic auth is used exactly once, to obtain the session id; the
    password is never sent again. Never logs the password or the session id.
    """
    host, username, password = _credentials()
    base_url = _rest_base_url(host)
    try:
        response = requests.post(f"{base_url}/api/session", auth=(username, password), timeout=30)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise VCenterAuthError(f"REST authentication failed: {exc}") from exc
    return base_url, response.json()


def rest_logout(base_url: str, session_id: str) -> None:
    try:
        requests.delete(f"{base_url}/api/session", headers={"vmware-api-session-id": session_id}, timeout=30)
    except requests.RequestException:
        pass  # best-effort cleanup only


def verify_rest_session(base_url: str, session_id: str) -> dict:
    """GET {base_url}/api/session - confirms the REST session is valid.

    Read-only: returns this session's own metadata only (user, created_time,
    last_accessed_time). Touches no inventory, authorization, or other state.
    """
    try:
        response = requests.get(f"{base_url}/api/session", headers={"vmware-api-session-id": session_id}, timeout=30)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise VCenterAuthError(f"REST session verification failed: {exc}") from exc
    return response.json()


def soap_login() -> object:
    """pyVmomi SmartConnect - separate vSphere Web Services API session.

    Uses its own username/password exchange; does not receive or reuse the
    REST session id.
    """
    host, username, password = _credentials()
    hostname = urlsplit(_rest_base_url(host)).hostname
    context = ssl.create_default_context()
    try:
        return SmartConnect(host=hostname, user=username, pwd=password, sslContext=context)
    except Exception as exc:  # pyVmomi raises vim.fault.* / socket errors, not one common base
        raise VCenterAuthError(f"SOAP authentication failed: {exc}") from exc


def soap_logout(service_instance: object) -> None:
    try:
        Disconnect(service_instance)
    except Exception:
        pass  # best-effort cleanup only


def verify_soap_session(service_instance: object) -> str:
    """ServiceInstance.CurrentTime() - confirms the SOAP session is valid.

    Read-only: returns the server's current time. No inventory or
    authorization side effects.
    """
    try:
        return str(service_instance.CurrentTime())
    except Exception as exc:
        raise VCenterAuthError(f"SOAP session verification failed: {exc}") from exc


def login() -> VCenterSession:
    """Establish REST and SOAP sessions independently. Neither call happens
    without the other having its own separate credential exchange."""
    base_url, rest_session_id = rest_login()
    service_instance = soap_login()
    return VCenterSession(rest_base_url=base_url, rest_session_id=rest_session_id, soap_service_instance=service_instance)


def get_session(session: VCenterSession) -> VCenterSession:
    return session


def logout(session: VCenterSession) -> None:
    rest_logout(session.rest_base_url, session.rest_session_id)
    soap_logout(session.soap_service_instance)
