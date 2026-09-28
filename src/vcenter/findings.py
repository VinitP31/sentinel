# vCenter deterministic security findings.
"""vCenter-specific deterministic security findings.

Computed only from what src/vcenter/normalize.py actually produced - never
invents privileges, roles, group membership, or activity. Mirrors the
existing Sentinel finding shape (principal / attribution / detail, see
src/analysis/rules.py) where it fits; vCenter-specific evidence fields are
added on top, not a replacement schema.

Administrator role name: the task spec that requested these findings said
to match role name == "Administrator". The real vCenter sandbox used
throughout this project's Phase 5/8 investigations shows the built-in
system role's actual name field is "Admin", not "Administrator" (observed
directly in real RetrieveEntityPermissions/roleList output, e.g.
roleId=-1, name="Admin", system=True). Both exact names are accepted here
so the finding fires against the real data as well as any vCenter that
literally names it "Administrator" - this is still an exact-match set, not
a substring/name-pattern match, so a custom role named "AdminRole" or
"DangerousRole" never matches.

One finding per rule, not one per principal or per entity: every principal
that matches a given rule (e.g. every Admin holder) is listed inside that
one finding's "principals" list, each carrying its own role/privileges/
assignments. A role granted with propagate=True at one entity is visible,
via inheritance, at every descendant entity authorization_collector
queried - normalize.py deduplicates this at the attachment level (the same
grant is not counted as multiple different entities), and this module
additionally groups all matching principals under one finding card rather
than one card each, since a real vCenter security review reads "7
principals have Admin" as one finding, not seven visually repetitive ones.

Severity is fixed, deterministic metadata per finding type (documented here
and in tests/test_vcenter_findings.py) - not derived from an AI model or
from a rule-name lookup table the way src/report/build.py's SEVERITY_RULES
works for AWS.
"""

ADMIN_ROLE_NAMES = frozenset({"Administrator", "Admin"})

SENSITIVE_AUTHORIZATION_PRIVILEGES = (
    "Authorization.ModifyPermissions",
    "Authorization.ModifyRoles",
    "Authorization.ReassignRolePermissions",
)

# vCenter's reserved system role ids are fixed across versions (-1 Admin,
# -2 ReadOnly, -3 View, -4 Anonymous, -5 NoAccess, ...) - -5/"NoAccess" is
# identified by this reserved id, never by name, so a custom role that
# happens to be named similarly can never match.
NO_ACCESS_ROLE_ID = "-5"

# Privilege ids that let the holder disrupt or reconfigure vCenter itself,
# independent of any single object's permissions - identified strictly by
# privilege id, same principle as SENSITIVE_AUTHORIZATION_PRIVILEGES above,
# never by a role's name. Confirmed against the real sandbox: the custom
# role "DangerousRole" carries all three, bound to one group
# ("platform-admins") at global scope.
HIGH_IMPACT_PRIVILEGES = (
    "Sessions.TerminateSession",
    "Global.Settings",
    "Host.Config.Settings",
)

VCENTER_ADMIN_001 = "VCENTER-ADMIN-001"
VCENTER_AUTH_001 = "VCENTER-AUTH-001"
VCENTER_NOACCESS_001 = "VCENTER-NOACCESS-001"
VCENTER_PRIV_001 = "VCENTER-PRIV-001"

# See src/vcenter/focused_graph.py: a role's full privilege list can be large
# (the built-in Admin role has hundreds); above this size the focused graph
# omits privilege nodes entirely rather than becoming unreadable.
MAX_GRAPH_PRIVILEGE_NODES = 6

# Privilege name prefixes that are worth surfacing directly in the report
# even when a role's full privilege list is too long to show in full (e.g.
# the built-in Admin role, ~464 privileges) - these are the ones most
# directly relevant to a security reviewer deciding whether access is
# appropriate. Not exhaustive, and never used to decide whether a finding
# fires (that is always based on the exact privileges present) - only to
# pick which few privileges to display first.
NOTABLE_PRIVILEGE_PREFIXES = (
    "Authorization.",
    "Permissions.",
    "Global.",
    "Certificate",
    "Host.Config.",
    "Host.Local.",
    "VirtualMachine.Config.",
    "Folder.Delete",
    "Datastore.Delete",
)

MAX_NOTABLE_PRIVILEGES = 10


def _principal_lookup(normalized: dict) -> dict:
    lookup = {}
    for record in normalized["users"] + normalized["groups"]:
        lookup[record["id"]] = record
    return lookup


def _policy_lookup(normalized: dict) -> dict:
    return {p["id"]: p for p in normalized["policies"]}


def _permissions_by_policy(normalized: dict) -> dict:
    by_policy: dict[str, list[dict]] = {}
    for permission in normalized["permissions"]:
        by_policy.setdefault(permission["policy_id"], []).append(permission)
    return by_policy


def _role_id_from_policy_id(policy_id: str) -> str:
    """Policy ids are f"{roleId}@{entityId}" for a bound role, or the bare
    str(roleId) for an unbound baseline policy (see normalize.py)."""
    return policy_id.split("@", 1)[0]


def _principal_record(principal_lookup: dict, principal_id: str) -> dict:
    record = principal_lookup.get(principal_id)
    if record is None:
        # Should not happen - normalize.py always registers every principal
        # seen in an attachment - but never invent an identity if it did.
        return {"id": principal_id, "name": principal_id, "type": "unknown"}
    return {"id": record["id"], "name": record["name"], "type": record["type"]}


def _actions_for_policy(permissions_by_policy: dict, policy_id: str) -> list[str]:
    permissions = permissions_by_policy.get(policy_id, [])
    if not permissions:
        return []
    return permissions[0]["actions"]


def _assignment(attachment: dict) -> dict:
    return {
        "entity_id": attachment["entity_id"],
        "entity_type": attachment["entity_type"],
        "entity_name": attachment["entity_name"],
        "propagate": attachment["propagate"],
        "attachment_type": attachment["attachment_type"],
    }


def _assignments_summary(assignments: list[dict]) -> str:
    direct = [a for a in assignments if a["attachment_type"] == "vcenter_direct"]
    inherited = [a for a in assignments if a["attachment_type"] == "vcenter_inherited"]

    def _label(a: dict) -> str:
        return a["entity_name"] or a["entity_id"]

    if len(assignments) == 1:
        kind = "directly" if assignments[0]["attachment_type"] == "vcenter_direct" else "via inheritance"
        return f"{_label(assignments[0])} ({kind})"

    parts = []
    if direct:
        parts.append(f"{_label(direct[0])} (direct)" + (f" and {len(direct) - 1} more direct" if len(direct) > 1 else ""))
    if inherited:
        parts.append(f"{len(inherited)} additional entit{'y' if len(inherited) == 1 else 'ies'} via inheritance")
    return ", ".join(parts) if parts else f"{len(assignments)} entities"


def curate_privileges(privileges: list[str], cap: int = MAX_NOTABLE_PRIVILEGES) -> tuple[list[str], int]:
    """A short, meaningful subset of a (possibly large) privilege list for
    display, plus the true total count - never silently drop the count.

    Privileges matching NOTABLE_PRIVILEGE_PREFIXES are shown first (they are
    the ones most relevant to a security reviewer); the remainder is padded
    alphabetically only if there is room left under cap. Every privilege in
    the input list is always the actual, collected privilege - nothing here
    invents or infers anything not already present.
    """
    total = len(privileges)
    if total <= cap:
        return sorted(privileges), total

    notable = sorted(p for p in privileges if p.startswith(NOTABLE_PRIVILEGE_PREFIXES))
    shown = notable[:cap]
    if len(shown) < cap:
        remaining = sorted(p for p in privileges if p not in shown)
        shown += remaining[: cap - len(shown)]
    return shown, total


def _principal_entry(attachment: dict, policy: dict, principal_lookup: dict, permissions_by_policy: dict) -> dict:
    role_id = _role_id_from_policy_id(attachment["policy_id"])
    principal = _principal_record(principal_lookup, attachment["principal_id"])
    privileges = _actions_for_policy(permissions_by_policy, attachment["policy_id"])
    return {
        "principal": principal,
        "role": {"id": role_id, "name": policy["name"], "system": policy["policy_type"] == "system"},
        "privileges": privileges,
        "assignments": [],  # filled in by the grouping step below
    }


def _group_by_principal_role(matches: list[tuple[dict, dict]], principal_lookup: dict, permissions_by_policy: dict) -> list[dict]:
    """matches: (attachment, policy) pairs that already passed a rule's
    filter -> one entry per (principal, role), each carrying every entity
    that principal+role combination is effective on."""
    groups: dict[tuple[str, str], dict] = {}
    for attachment, policy in matches:
        role_id = _role_id_from_policy_id(attachment["policy_id"])
        key = (attachment["principal_id"], role_id)
        entry = groups.get(key)
        if entry is None:
            entry = _principal_entry(attachment, policy, principal_lookup, permissions_by_policy)
            groups[key] = entry
        entry["assignments"].append(_assignment(attachment))

    entries = list(groups.values())
    for entry in entries:
        entry["assignments"].sort(key=lambda a: (a["attachment_type"], a["entity_id"]))
        entry["assignments_summary"] = _assignments_summary(entry["assignments"])
    entries.sort(key=lambda e: e["principal"]["name"])
    return entries


def _admin_detail(principals: list[dict], role_name: str) -> str:
    """"N principals hold the role" alone reads as N equivalent human
    users, when the group is actually reported once as itself (see
    _group_by_principal_role - no member expansion) - counting it the
    same as a named user or service account overstates who is actually
    affected. Break out how many of the affected authorization subjects
    are a group versus a user/service account whenever at least one group
    is present; otherwise use the plain count (no group to distinguish)."""
    group_count = sum(1 for p in principals if p["principal"]["type"] == "group")
    other_count = len(principals) - group_count
    verb = "hold" if len(principals) != 1 else "holds"
    if group_count == 0:
        return f"{len(principals)} principal{'s' if len(principals) != 1 else ''} {verb} the built-in {role_name} role."
    subject_noun = "authorization subject" if len(principals) == 1 else "authorization subjects"
    group_phrase = f"{group_count} group{'s' if group_count != 1 else ''}"
    if other_count:
        other_phrase = f"{other_count} user/service account{'s' if other_count != 1 else ''}"
        breakdown = f"{other_phrase} and {group_phrase}"
    else:
        breakdown = group_phrase
    return f"{len(principals)} {subject_noun} {verb} the built-in {role_name} role, including {breakdown}."


def find_administrative_access(normalized: dict) -> list[dict]:
    """VCENTER-ADMIN-001: one finding covering every principal whose role is
    the built-in/system Administrator role, identified by role.system ==
    True and role.name in ADMIN_ROLE_NAMES (exact match only - never a name
    pattern match, so a custom role like "AdminRole" never qualifies).

    A group permission is reported as a group entry, not as access
    belonging to every group member - group membership is not collected
    and is never inferred here. Returns [] if no principal matches -
    nothing is ever manufactured.
    """
    principal_lookup = _principal_lookup(normalized)
    policy_lookup = _policy_lookup(normalized)
    permissions_by_policy = _permissions_by_policy(normalized)

    matches = []
    for attachment in normalized["attachments"]:
        policy = policy_lookup.get(attachment["policy_id"])
        if policy is None:
            continue
        if policy["policy_type"] != "system" or policy["name"] not in ADMIN_ROLE_NAMES:
            continue
        matches.append((attachment, policy))

    if not matches:
        return []

    principals = _group_by_principal_role(matches, principal_lookup, permissions_by_policy)
    role_name = principals[0]["role"]["name"]
    full_privileges = principals[0]["privileges"]
    notable, total = curate_privileges(full_privileges)
    detail = _admin_detail(principals, role_name)

    return [
        {
            "id": VCENTER_ADMIN_001,
            "rule": "vcenter_administrative_access",
            "title": "Administrative Access",
            "severity": "high",
            "principals": principals,
            "role_name": role_name,
            "total_privilege_count": total,
            "notable_privileges": notable,
            "detail": detail,
        }
    ]


def find_authorization_management_access(normalized: dict) -> list[dict]:
    """VCENTER-AUTH-001: one finding covering every principal whose role
    contains one or more real, documented Authorization-management
    privileges, identified strictly by privilege ID - never by role name.

    Administrator itself is excluded here (it already carries these
    privileges by virtue of holding everything) so it is reported only
    once, as VCENTER-ADMIN-001, not double-counted under this rule too.
    Returns [] if no principal matches.
    """
    principal_lookup = _principal_lookup(normalized)
    policy_lookup = _policy_lookup(normalized)
    permissions_by_policy = _permissions_by_policy(normalized)

    matches = []
    for attachment in normalized["attachments"]:
        policy = policy_lookup.get(attachment["policy_id"])
        if policy is None:
            continue
        if policy["policy_type"] == "system" and policy["name"] in ADMIN_ROLE_NAMES:
            continue

        actions = _actions_for_policy(permissions_by_policy, attachment["policy_id"])
        if not any(p in actions for p in SENSITIVE_AUTHORIZATION_PRIVILEGES):
            continue

        matches.append((attachment, policy))

    if not matches:
        return []

    principals = _group_by_principal_role(matches, principal_lookup, permissions_by_policy)
    # This rule's evidence is the sensitive privilege(s) actually matched,
    # not the role's full action list - always a short, precise set.
    for entry in principals:
        entry["privileges"] = [p for p in entry["privileges"] if p in SENSITIVE_AUTHORIZATION_PRIVILEGES]

    all_sensitive = sorted({p for entry in principals for p in entry["privileges"]})
    verb = "hold" if len(principals) != 1 else "holds"
    # "permissions or roles" is only accurate when Authorization.ModifyRoles
    # is one of the actually-detected privileges - Authorization.
    # ModifyPermissions alone never touches role definitions, only who is
    # granted access, so this must never claim more than what was detected.
    modifies = "permissions or roles" if "Authorization.ModifyRoles" in all_sensitive else "permissions"
    detail = (
        f"{len(principals)} principal{'s' if len(principals) != 1 else ''} {verb} a role containing "
        f"{', '.join(all_sensitive)}, which allows modification of vCenter {modifies}."
    )

    return [
        {
            "id": VCENTER_AUTH_001,
            "rule": "vcenter_authorization_management_access",
            "title": "Authorization Management Access",
            "severity": "medium",
            "principals": principals,
            "sensitive_privileges": all_sensitive,
            "detail": detail,
        }
    ]


def find_no_access_override(normalized: dict) -> list[dict]:
    """VCENTER-NOACCESS-001: one finding covering every principal holding an
    explicit No Access assignment (roleId == NO_ACCESS_ROLE_ID, the reserved
    system role id - never matched by name).

    No Access is vCenter's own explicit-deny mechanism: at the entity where
    it is assigned, it takes precedence over whatever would otherwise apply
    to that principal there (an inherited or group-based grant), per
    vCenter's documented permission precedence. This finding reports only
    the explicit restriction actually observed - it does not identify what,
    if anything, it overrides (that would require effective-access
    computation, out of scope - see src/vcenter/CLAUDE.md), and it is
    reported as a restriction to verify, never asserted as a vulnerability.
    Returns [] if no principal matches.
    """
    principal_lookup = _principal_lookup(normalized)
    policy_lookup = _policy_lookup(normalized)
    permissions_by_policy = _permissions_by_policy(normalized)

    matches = []
    for attachment in normalized["attachments"]:
        policy = policy_lookup.get(attachment["policy_id"])
        if policy is None:
            continue
        if policy["policy_type"] != "system":
            continue
        if _role_id_from_policy_id(attachment["policy_id"]) != NO_ACCESS_ROLE_ID:
            continue
        matches.append((attachment, policy))

    if not matches:
        return []

    principals = _group_by_principal_role(matches, principal_lookup, permissions_by_policy)
    subject_noun = "authorization subject" if len(principals) == 1 else "authorization subjects"
    verb = "holds" if len(principals) == 1 else "hold"
    detail = (
        f"{len(principals)} {subject_noun} {verb} an explicit No Access assignment, which overrides "
        f"any otherwise-applicable access for that principal at the entity where it is assigned. This "
        f"is reported as an explicit access restriction to verify, not asserted as a vulnerability."
    )

    return [
        {
            "id": VCENTER_NOACCESS_001,
            "rule": "vcenter_no_access_override",
            "title": "No Access Override",
            "severity": "medium",
            "principals": principals,
            "detail": detail,
        }
    ]


def find_high_impact_privilege_access(normalized: dict) -> list[dict]:
    """VCENTER-PRIV-001: one finding covering every non-Admin-role principal
    whose role contains one or more of HIGH_IMPACT_PRIVILEGES, identified
    strictly by privilege id - never by role name (a role named
    "DangerousRole" is judged only by its actual privileges, same principle
    as VCENTER-AUTH-001).

    Administrator is excluded (already reported once, as VCENTER-ADMIN-001,
    not double-counted here). A role carrying one of these privileges but
    never actually bound to any principal produces no attachment record and
    therefore never appears here - only real, observed bindings are ever
    reported. Returns [] if no principal matches.
    """
    principal_lookup = _principal_lookup(normalized)
    policy_lookup = _policy_lookup(normalized)
    permissions_by_policy = _permissions_by_policy(normalized)

    matches = []
    for attachment in normalized["attachments"]:
        policy = policy_lookup.get(attachment["policy_id"])
        if policy is None:
            continue
        if policy["policy_type"] == "system" and policy["name"] in ADMIN_ROLE_NAMES:
            continue

        actions = _actions_for_policy(permissions_by_policy, attachment["policy_id"])
        if not any(p in actions for p in HIGH_IMPACT_PRIVILEGES):
            continue

        matches.append((attachment, policy))

    if not matches:
        return []

    principals = _group_by_principal_role(matches, principal_lookup, permissions_by_policy)
    # This rule's evidence is the high-impact privilege(s) actually matched,
    # not the role's full action list - always a short, precise set.
    for entry in principals:
        entry["privileges"] = [p for p in entry["privileges"] if p in HIGH_IMPACT_PRIVILEGES]

    all_high_impact = sorted({p for entry in principals for p in entry["privileges"]})
    verb = "hold" if len(principals) != 1 else "holds"
    detail = (
        f"{len(principals)} principal{'s' if len(principals) != 1 else ''} {verb} a role containing "
        f"one or more high-impact privileges ({', '.join(all_high_impact)}), each capable of "
        f"terminating other sessions or modifying vCenter-wide or host configuration."
    )

    return [
        {
            "id": VCENTER_PRIV_001,
            "rule": "vcenter_high_impact_privilege_access",
            "title": "High-Impact Privilege Access",
            "severity": "high",
            "principals": principals,
            "high_impact_privileges": all_high_impact,
            "detail": detail,
        }
    ]


def run_all(normalized: dict) -> list[dict]:
    return (
        find_administrative_access(normalized)
        + find_authorization_management_access(normalized)
        + find_no_access_override(normalized)
        + find_high_impact_privilege_access(normalized)
    )
