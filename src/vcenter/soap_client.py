# vCenter SOAP API client.
"""Thin, read-only wrapper over the vSphere Web Services (SOAP) API, via pyVmomi.

Authentication/session lifecycle lives in src/vcenter/auth.py (SmartConnect /
Disconnect) - this module only wraps an already-established ServiceInstance
for read operations. It does not log in, reconnect, or log out a session
itself.

Only specific, named read operations are exposed here - no generic "call any
method by name" dispatcher - since SOAP method names do not map cleanly to
read/write (src/vcenter/CLAUDE.md section 7): a generic dispatcher could
reach a mutating manager just as easily as a read-only one. Authorization-
specific reads (roles, privileges, permissions) are out of scope for this
phase; they belong to Phase 5, once each specific operation's read-only
status is individually verified against documentation.
"""

from dataclasses import dataclass, field


class VCenterSoapError(RuntimeError):
    """A SOAP call to vCenter failed."""


@dataclass
class VCenterSoapClient:
    """Issues read-only calls against an already-authenticated ServiceInstance.

    service_instance comes from src.vcenter.auth.soap_login() - this class
    does not authenticate or manage session lifecycle itself.
    """

    service_instance: object
    _content: object = field(default=None, init=False, repr=False)

    @property
    def content(self):
        """ServiceContent - read-only root of every manager (PropertyCollector,
        AuthorizationManager, etc), fetched once and cached. Retrieving this
        reference does not itself read or modify any managed object; it is
        the starting point later phases use for individually-verified reads.
        """
        if self._content is None:
            try:
                self._content = self.service_instance.RetrieveContent()
            except Exception as exc:
                raise VCenterSoapError(f"RetrieveContent() failed: {exc}") from exc
        return self._content

    def current_time(self) -> str:
        """ServiceInstance.CurrentTime() - confirms the session is live.

        Read-only: returns the server's current time. No parameters, no
        side effects, not part of any mutating manager.
        """
        try:
            return str(self.service_instance.CurrentTime())
        except Exception as exc:
            raise VCenterSoapError(f"CurrentTime() failed: {exc}") from exc
