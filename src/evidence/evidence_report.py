"""Collection Evidence PDF: a polished, human-readable rendering of an
already-written collection_evidence.json.

This proves what Sentinel actually collected - it is not a security
assessment. It never includes a finding, a severity, a recommendation, an AI
explanation, or a "why this matters" narrative; those belong entirely to the
existing security report (src/report/build.py for AWS, src/vcenter/report.py
for vCenter), which this module never touches and never reads.

Reads only the evidence dict already written to disk by
src/evidence/collection_evidence.py - never recomputes a collected fact,
never reconnects to any provider. Everything this module derives for
presentation (group membership tables, policy statement summaries, a
CAN_ASSUME-style access-path diagram for AWS, role/privilege categorization
and representative permission rows for vCenter) is computed purely from
fields already present in that JSON - nothing is invented, inferred beyond
what the data itself states, or written back to the JSON. The JSON stays
the single source of truth; this file only changes how it is presented.
"""

import html
import json
import math
import re
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote

from PIL import Image, ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as canvas_module
from reportlab.platypus import Image as ReportlabImage
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# --- constants --------------------------------------------------------------

MAX_RECORD_ROWS = 14
MAX_PERMISSION_ROWS = 8
MAX_ACCESS_MAP_ROWS = 8
MAX_POLICY_ROWS = 20

# Helvetica/Helvetica-Bold are 2 of the 14 PDF standard fonts - guaranteed
# present in every compliant viewer with no embedding needed, so they render
# identically everywhere. An embedded TrueType alternative (e.g. the
# system's own Arial) was tried and confirmed clean too, but was reverted:
# it isn't ours to freely embed/redistribute in a generated document, and
# it wasn't the source of the rendering issue this project actually hit
# (see FONT_REGULAR/FONT_BOLD history) - that turned out to be a table grid
# line (see _metric_cards).
FONT_REGULAR, FONT_BOLD = "Helvetica", "Helvetica-Bold"

INK = colors.HexColor("#172B4D")
MUTED = colors.HexColor("#6B778C")
BORDER = colors.HexColor("#DFE1E6")
CARD_BG = colors.HexColor("#F4F5F7")
CALLOUT_BG = colors.HexColor("#EAF0FF")
CALLOUT_BORDER = colors.HexColor("#C1D4F5")
ACCENT = colors.HexColor("#0052CC")
GOOD = colors.HexColor("#00875A")
BAD = colors.HexColor("#DE350B")

_TABLE_STYLE = TableStyle(
    [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
)
_CELL_STYLE = ParagraphStyle("evidenceCell", fontName=FONT_REGULAR, fontSize=8, leading=10)
_TITLE_STYLE = ParagraphStyle("evidenceTitle", fontName=FONT_BOLD, fontSize=19, leading=23, textColor=INK, spaceAfter=3)
_SUBTITLE_STYLE = ParagraphStyle("evidenceSubtitle", fontName=FONT_REGULAR, fontSize=11, textColor=MUTED, spaceAfter=12)
_KV_STYLE = ParagraphStyle("evidenceKv", fontName=FONT_REGULAR, fontSize=9.5, textColor=INK, leading=14)
_H2_TEXT_STYLE = ParagraphStyle("evidenceH2Text", fontName=FONT_BOLD, fontSize=13.5, textColor=INK)
_H3_STYLE = ParagraphStyle("evidenceH3", fontName=FONT_BOLD, fontSize=10.5, textColor=INK, spaceBefore=10, spaceAfter=4)
_NOTE_STYLE = ParagraphStyle("evidenceNote", fontName=FONT_REGULAR, fontSize=8.5, textColor=MUTED, spaceBefore=2, spaceAfter=6)
_CARD_NUMBER_STYLE = ParagraphStyle("evidenceCardNumber", fontName=FONT_BOLD, fontSize=20, alignment=1, textColor=INK)
_CARD_LABEL_STYLE = ParagraphStyle("evidenceCardLabel", fontName=FONT_REGULAR, fontSize=7.7, alignment=1, textColor=MUTED)
_CALLOUT_STYLE = ParagraphStyle("evidenceCallout", fontName=FONT_REGULAR, fontSize=9, textColor=INK, leading=13)
_CALLOUT_EYEBROW_STYLE = ParagraphStyle("evidenceCalloutEyebrow", fontName=FONT_BOLD, fontSize=8, textColor=ACCENT, spaceAfter=3)

_PAGE_SIDE_MARGIN = 0.6 * inch
_PAGE_TOP_MARGIN = 0.85 * inch
_PAGE_BOTTOM_MARGIN = 0.7 * inch
_CONTENT_WIDTH = LETTER[0] - _PAGE_SIDE_MARGIN * 2

TITLES = {
    "aws": "Sentinel - AWS Collection Evidence",
    "vcenter": "Sentinel - vCenter Collection Evidence",
}

_TRUNCATE_AT = 60


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _short(value, limit: int = _TRUNCATE_AT) -> str:
    text = str(value) if value is not None else ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _cell(value) -> Paragraph:
    return Paragraph(_esc(_short(value)), _CELL_STYLE)


def _human_date(raw) -> str:
    try:
        return datetime.fromisoformat(str(raw)).strftime("%B %d, %Y %H:%M UTC")
    except (ValueError, TypeError):
        return str(raw)


# --- shared building blocks --------------------------------------------------


def _section_heading(text: str) -> Table:
    """A section heading with a rule beneath it - a Table rather than a bare
    Paragraph so the rule is guaranteed to sit directly under the text."""
    table = Table([[Paragraph(_esc(text), _H2_TEXT_STYLE)]], colWidths=[_CONTENT_WIDTH])
    table.setStyle(
        TableStyle(
            [
                ("TOPPADDING", (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 1.2, INK),
            ]
        )
    )
    return table


def _metric_cards(items: list[tuple[str, object]], per_row: int = 4) -> list:
    """A row (or several rows) of bordered metric cards: a large number over
    a small label. Purely a display of counts already present in the
    evidence dict - never a derived or estimated figure."""
    story = []
    for start in range(0, len(items), per_row):
        chunk = items[start : start + per_row]
        while len(chunk) < per_row:
            chunk.append(("", ""))
        numbers = [Paragraph(_esc(value), _CARD_NUMBER_STYLE) if value != "" else "" for _label, value in chunk]
        labels = [Paragraph(_esc(label), _CARD_LABEL_STYLE) if label != "" else "" for label, _value in chunk]
        col_width = _CONTENT_WIDTH / per_row
        table = Table([numbers, labels], colWidths=[col_width] * per_row, rowHeights=[32, 20])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
                    # Vertical dividers between cards only - never a
                    # horizontal line between a card's own number and its
                    # label. INNERGRID drew one there too, sitting close
                    # enough to both lines of text to read as a stray
                    # strikethrough/underline through the numbers and
                    # labels - confirmed by rendering this table in
                    # isolation and comparing to the fixed version.
                    ("LINEAFTER", (0, 0), (-2, -1), 0.75, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
                    ("TOPPADDING", (0, 1), (-1, 1), 2),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 6))
    return story


def _callout(eyebrow: str, body_lines: list[str]) -> Table:
    """A light blue callout box - used for the Normalized Common Model note
    and the closing Evidence Completeness page, mirroring the narrative-box
    treatment already used in the vCenter security report for visual
    consistency across Sentinel's PDFs."""
    content = [Paragraph(_esc(eyebrow), _CALLOUT_EYEBROW_STYLE)]
    content.extend(Paragraph(_esc(line), _CALLOUT_STYLE) for line in body_lines)
    table = Table([[content]], colWidths=[_CONTENT_WIDTH])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CALLOUT_BG),
                ("BOX", (0, 0), (-1, -1), 0.75, CALLOUT_BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _compact_table(records: list[dict], columns: list[tuple[str, str]], max_rows: int = MAX_RECORD_ROWS, note: str | None = None) -> list:
    """columns: list of (header_label, dict_key). A missing key renders
    blank, never invented. Shows at most max_rows; the note (if given)
    explains where the rest of the real data lives - never a bare developer-
    style truncation message."""
    if not records:
        return [Paragraph("No records collected.", _NOTE_STYLE)]

    shown = records[:max_rows]
    header = [label for label, _key in columns]
    rows = [[_cell(record.get(key, "")) for _label, key in columns] for record in shown]
    col_width = _CONTENT_WIDTH / len(columns)
    table = Table([header] + rows, colWidths=[col_width] * len(columns), repeatRows=1)
    table.setStyle(_TABLE_STYLE)

    story: list = [table]
    if len(records) > max_rows:
        remaining = len(records) - max_rows
        story.append(
            Paragraph(
                note or f"{remaining} additional record(s) omitted from this view. The complete set is retained in the underlying collection record.",
                _NOTE_STYLE,
            )
        )
    return story


def _kept_subsection(heading: str, body: list) -> KeepTogether:
    """A subsection heading plus the flowables that belong to it, kept on
    one page together - without this, a heading can land at the very
    bottom of a page with its table pushed to the next, which reads as a
    layout mistake rather than one subsection."""
    return KeepTogether([Paragraph(_esc(heading), _H3_STYLE), *body])


def _identity_block(evidence: dict, extra_lines: list[str]) -> list:
    statuses = evidence.get("collection_status", [])
    complete = all(status.get("succeeded") for status in statuses) if statuses else True
    status_label = "Complete" if complete else "Completed with gaps"
    lines = [
        f"<b>Collection timestamp:</b> {_esc(_human_date(evidence.get('collected_at')))}",
        f"<b>Collection status:</b> {_esc(status_label)}",
        "<b>Access mode:</b> Read-only",
        *extra_lines,
    ]
    return [Paragraph(line, _KV_STYLE) for line in lines]


def _normalized_model_callout(evidence: dict, caption: str | None = None) -> Table:
    counts = evidence.get("normalized_counts", {})
    order = ("users", "groups", "roles", "policies", "permissions", "attachments", "memberships")
    parts = ", ".join(f"{key.title()} {counts.get(key, 0)}" for key in order)
    lines = [f"{parts}."]
    if caption:
        lines.append(caption)
    return _callout("Normalized Common Model (shared Sentinel data model, not the provider's own inventory)", lines)


def _numbered_canvas_factory(title: str):
    """A reportlab canvas subclass that draws a slim header (report title,
    page number) and footer (a one-line reminder of what this document is)
    on every page. Two-pass build (the standard reportlab pattern) so the
    footer can read 'Page X of Y' - the total page count isn't known until
    every page has already been laid out once."""

    class _NumberedCanvas(canvas_module.Canvas):
        def __init__(self, *args, **kwargs):
            canvas_module.Canvas.__init__(self, *args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_chrome(total_pages)
                canvas_module.Canvas.showPage(self)
            canvas_module.Canvas.save(self)

        def _draw_chrome(self, total_pages: int) -> None:
            width, height = LETTER
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.75)
            self.line(_PAGE_SIDE_MARGIN, height - 0.55 * inch, width - _PAGE_SIDE_MARGIN, height - 0.55 * inch)
            self.setFont(FONT_REGULAR, 8)
            self.setFillColor(MUTED)
            self.drawString(_PAGE_SIDE_MARGIN, height - 0.45 * inch, title)
            self.drawRightString(width - _PAGE_SIDE_MARGIN, height - 0.45 * inch, f"Page {self._pageNumber} of {total_pages}")

            self.line(_PAGE_SIDE_MARGIN, 0.5 * inch, width - _PAGE_SIDE_MARGIN, 0.5 * inch)
            self.drawString(_PAGE_SIDE_MARGIN, 0.35 * inch, "Read-only Collection Evidence. Not a security assessment.")
            self.drawRightString(width - _PAGE_SIDE_MARGIN, 0.35 * inch, "Generated by Sentinel")

    return _NumberedCanvas


# --- AWS: presentation-only derivation over already-collected records ------


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document: dict | None) -> list[dict]:
    if not document:
        return []
    return _as_list(document.get("Statement", []))


def _policy_index(policies: list[dict]) -> dict[str, dict]:
    return {policy["Arn"]: policy for policy in policies if policy.get("Arn")}


def _policy_document(policy_ref: dict, policy_index: dict) -> dict | None:
    """Resolves a policy reference (managed: {PolicyName, PolicyArn}, or
    inline: {PolicyName, PolicyDocument}) to its document, using only
    documents already present in this evidence's Policies section - returns
    None rather than inventing a document that wasn't actually collected."""
    if "PolicyDocument" in policy_ref:
        document = policy_ref["PolicyDocument"]
    else:
        policy = policy_index.get(policy_ref.get("PolicyArn"))
        if not policy:
            return None
        versions = policy.get("PolicyVersionList", [])
        default = next((v for v in versions if v.get("IsDefaultVersion")), versions[0] if versions else None)
        document = default.get("Document") if default else None
    if isinstance(document, str):
        try:
            document = json.loads(unquote(document))
        except (ValueError, TypeError):
            return None
    return document


def _summarize_policy_document(document: dict | None) -> str:
    """One short line per statement (e.g. 'Allow s3:GetObject, s3:ListBucket
    on arn:...') built directly from the statement actually collected.
    Wildcards are shown exactly as written, never expanded into the
    individual actions they cover."""
    lines = []
    for statement in _statements(document):
        effect = statement.get("Effect", "Allow")
        actions = ", ".join(_as_list(statement.get("Action"))) or "(no action)"
        resources = _as_list(statement.get("Resource"))
        resource_text = resources[0] if len(resources) == 1 else (", ".join(resources) if resources else "*")
        lines.append(f"{effect} {actions} on {_short(resource_text, 70)}")
    return " | ".join(lines) if lines else "No statements collected."


_PATTERN_CHECKS = (
    ("sts:AssumeRole", lambda s: "sts:assumerole" in [a.lower() for a in _as_list(s.get("Action"))]),
    ("Wildcard Allow", lambda s: s.get("Effect") == "Allow" and ("*" in _as_list(s.get("Action")) or s.get("Resource") == "*")),
    ("Explicit Deny", lambda s: s.get("Effect") == "Deny"),
    ("S3 Read/List", lambda s: any(a.lower().startswith(("s3:get", "s3:list")) for a in _as_list(s.get("Action")))),
)


def _policy_patterns(document: dict | None) -> list[str]:
    found = []
    for statement in _statements(document):
        for label, check in _PATTERN_CHECKS:
            if check(statement) and label not in found:
                found.append(label)
    return found


def _aws_identity_inventory(records: dict) -> tuple[list[dict], list[dict]]:
    users = records.get("users", [])
    groups = records.get("groups", [])

    group_members: dict[str, list[str]] = {group["GroupName"]: [] for group in groups}
    for user in users:
        for group_name in user.get("GroupList", []):
            group_members.setdefault(group_name, []).append(user["UserName"])

    user_rows = [
        {
            "User": user["UserName"],
            "Groups": ", ".join(user.get("GroupList", [])) or "-",
            "Direct Policies": ", ".join(
                [ref["PolicyName"] for ref in user.get("AttachedManagedPolicies", [])] + [ref["PolicyName"] for ref in user.get("UserPolicyList", [])]
            )
            or "-",
        }
        for user in users
    ]
    group_rows = [
        {
            "Group": group["GroupName"],
            "Members": ", ".join(group_members.get(group["GroupName"], [])) or "(none collected)",
            "Attached Policies": ", ".join(
                [ref["PolicyName"] for ref in group.get("AttachedManagedPolicies", [])] + [ref["PolicyName"] for ref in group.get("GroupPolicyList", [])]
            )
            or "-",
        }
        for group in groups
    ]
    return user_rows, group_rows


def _aws_policy_table_rows(records: dict) -> list[dict]:
    """One row per distinct policy name actually collected, combining every
    holder it was seen attached to (a managed policy can be attached to more
    than one user/group/role) - never a policy or a holder invented."""
    policies = records.get("policies", [])
    policy_index = _policy_index(policies)

    grouped: dict[str, dict] = {}

    def _add(entries, holder_label, kind):
        for ref in entries:
            name = ref.get("PolicyName")
            if not name:
                continue
            entry = grouped.setdefault(name, {"kind": kind, "holders": [], "document": None})
            entry["holders"].append(holder_label)
            if entry["document"] is None:
                entry["document"] = _policy_document(ref, policy_index)

    for user in records.get("users", []):
        _add(user.get("AttachedManagedPolicies", []), f"{user['UserName']} (user)", "Managed")
        _add(user.get("UserPolicyList", []), f"{user['UserName']} (user)", "Inline")
    for group in records.get("groups", []):
        _add(group.get("AttachedManagedPolicies", []), f"{group['GroupName']} (group)", "Managed")
        _add(group.get("GroupPolicyList", []), f"{group['GroupName']} (group)", "Inline")
    for role in records.get("roles", []):
        _add(role.get("AttachedManagedPolicies", []), f"{role['RoleName']} (role)", "Managed")
        _add(role.get("RolePolicyList", []), f"{role['RoleName']} (role)", "Inline")

    rows = []
    for name, entry in grouped.items():
        document = entry["document"]
        rows.append(
            {
                "Policy": f"{name} ({entry['kind']})",
                "Attached To": ", ".join(entry["holders"]),
                "Summary": _summarize_policy_document(document),
                "Patterns": ", ".join(_policy_patterns(document)) or "-",
            }
        )
    return rows


_ARN_ROLE_RE = re.compile(r"^arn:aws:iam::\d+:role/(.+)$")


def _role_name_from_arn(arn: str) -> str | None:
    match = _ARN_ROLE_RE.match(arn)
    return match.group(1) if match else None


def _principal_name_from_arn(arn: str) -> str:
    for prefix in ("user/", "role/"):
        index = arn.find(prefix)
        if index != -1:
            return arn[index + len(prefix) :]
    return arn


def _trusted_principals(role: dict) -> set[str]:
    trusted = set()
    for statement in _statements(role.get("AssumeRolePolicyDocument")):
        if statement.get("Effect") != "Allow":
            continue
        if "sts:assumerole" not in [a.lower() for a in _as_list(statement.get("Action"))]:
            continue
        principal = statement.get("Principal", {})
        aws_principal = principal.get("AWS") if isinstance(principal, dict) else None
        trusted.update(_as_list(aws_principal))
    return trusted


def _assume_grants(document: dict | None) -> set[str]:
    """Role ARNs this document actually grants sts:AssumeRole on - resource
    values are used exactly as collected, never expanded from a wildcard."""
    granted = set()
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        if "sts:assumerole" not in [a.lower() for a in _as_list(statement.get("Action"))]:
            continue
        for resource in _as_list(statement.get("Resource")):
            if _role_name_from_arn(resource):
                granted.add(resource)
    return granted


def _aws_access_paths(records: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(edges, blocked). An edge exists only when a policy grant AND the
    target role's trust policy agree - the same two-sided rule the rest of
    Sentinel enforces for CAN_ASSUME (a grant alone describes a path that
    does not work, and is shown here as blocked, never as a real edge).
    Derived only from AssumeRolePolicyDocument and policy documents already
    present in this evidence - no relationship is assumed or invented, and
    nothing here is specific to any particular user or role name."""
    roles = records.get("roles", [])
    policy_index = _policy_index(records.get("policies", []))
    role_trust = {role["Arn"]: _trusted_principals(role) for role in roles}

    grants: dict[str, set[str]] = {}

    def _collect(principal_arn: str, entries: list[dict]):
        for ref in entries:
            grants.setdefault(principal_arn, set()).update(_assume_grants(_policy_document(ref, policy_index)))

    for user in records.get("users", []):
        _collect(user["Arn"], user.get("AttachedManagedPolicies", []) + user.get("UserPolicyList", []))
    for role in roles:
        _collect(role["Arn"], role.get("AttachedManagedPolicies", []) + role.get("RolePolicyList", []))

    group_grants: dict[str, set[str]] = {}
    for group in records.get("groups", []):
        granted = set()
        for ref in group.get("AttachedManagedPolicies", []) + group.get("GroupPolicyList", []):
            granted.update(_assume_grants(_policy_document(ref, policy_index)))
        group_grants[group["GroupName"]] = granted
    for user in records.get("users", []):
        for group_name in user.get("GroupList", []):
            grants.setdefault(user["Arn"], set()).update(group_grants.get(group_name, set()))

    edges, blocked = [], []
    for principal_arn, granted_roles in grants.items():
        principal_name = _principal_name_from_arn(principal_arn)
        for role_arn in granted_roles:
            role_name = _role_name_from_arn(role_arn) or role_arn
            if principal_arn in role_trust.get(role_arn, set()):
                edges.append((principal_name, role_name))
            else:
                blocked.append((principal_name, role_name))
    return edges, blocked


def _load_diagram_font(size: int):
    for candidate in ("/System/Library/Fonts/Helvetica.ttc", "/System/Library/Fonts/Supplemental/Arial.ttf"):
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _render_access_path_png(edges: list[tuple[str, str]], blocked: list[tuple[str, str]]) -> bytes | None:
    """A small left-to-right box-and-arrow diagram of real CAN_ASSUME edges
    (green, solid) and real blocked grants (red, dashed) - drawn only from
    the edges/blocked pairs already derived from collected data."""
    if not edges and not blocked:
        return None

    nodes: list[str] = []
    for source, target in edges + blocked:
        if source not in nodes:
            nodes.append(source)
        if target not in nodes:
            nodes.append(target)

    depth = {node: 0 for node in nodes}
    changed = True
    while changed:
        changed = False
        for source, target in edges:
            if depth[target] < depth[source] + 1:
                depth[target] = depth[source] + 1
                changed = True
    for source, target in blocked:
        if depth[target] < depth[source] + 1:
            depth[target] = depth[source] + 1

    layers: dict[int, list[str]] = {}
    for node in nodes:
        layers.setdefault(depth[node], []).append(node)

    box_w, box_h = 176, 44
    col_gap, row_gap = 70, 60
    max_rows = max(len(members) for members in layers.values())
    width = int((max(layers) + 1) * (box_w + col_gap) + col_gap)
    height = int(max_rows * (box_h + row_gap) + row_gap)

    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = _load_diagram_font(14)

    positions: dict[str, tuple[int, int, int, int]] = {}
    for col, members in layers.items():
        for row, name in enumerate(members):
            x = col_gap + col * (box_w + col_gap)
            y = row_gap + row * (box_h + row_gap)
            positions[name] = (x, y, x + box_w, y + box_h)

    for name, coords in positions.items():
        draw.rounded_rectangle(coords, radius=8, outline="#0052CC", width=2, fill="#F4F5F7")
        text = _short(name, 24)
        bbox = draw.textbbox((0, 0), text, font=font)
        text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        cx, cy = (coords[0] + coords[2]) / 2, (coords[1] + coords[3]) / 2
        draw.text((cx - text_w / 2, cy - text_h / 2), text, fill="#172B4D", font=font)

    def _edge_point(name: str, side: str) -> tuple[float, float]:
        x1, y1, x2, y2 = positions[name]
        cy = (y1 + y2) / 2
        return (x2, cy) if side == "right" else (x1, cy)

    def _draw_arrow(p1, p2, color, dashed=False, label=None):
        x1, y1 = p1
        x2, y2 = p2
        if dashed:
            distance = math.hypot(x2 - x1, y2 - y1)
            steps = max(int(distance / 9), 1)
            for i in range(0, steps, 2):
                sx, sy = x1 + (x2 - x1) * i / steps, y1 + (y2 - y1) * i / steps
                ex, ey = x1 + (x2 - x1) * (i + 1) / steps, y1 + (y2 - y1) * (i + 1) / steps
                draw.line([(sx, sy), (ex, ey)], fill=color, width=2)
        else:
            draw.line([(x1, y1), (x2, y2)], fill=color, width=2)
        angle = math.atan2(y2 - y1, x2 - x1)
        for delta in (0.4, -0.4):
            ax = x2 - 10 * math.cos(angle - delta)
            ay = y2 - 10 * math.sin(angle - delta)
            draw.line([(x2, y2), (ax, ay)], fill=color, width=2)
        if label:
            label_font = _load_diagram_font(11)
            # Perpendicular offset from the line's own direction, not a
            # fixed vertical shift - keeps the label off the line and off
            # the boxes regardless of whether the line is horizontal or
            # diagonal (a diagonal blocked edge previously overlapped the
            # adjacent solid edge and the box it passed near).
            angle = math.atan2(y2 - y1, x2 - x1)
            perp_x, perp_y = -math.sin(angle), math.cos(angle)
            mid_x, mid_y = x1 + (x2 - x1) * 0.5, y1 + (y2 - y1) * 0.5
            bbox = draw.textbbox((0, 0), label, font=label_font)
            label_w = bbox[2] - bbox[0]
            offset = 16 if perp_y <= 0 else -16
            draw.text((mid_x - label_w / 2 + perp_x * offset, mid_y + perp_y * offset - 6), label, fill=color, font=label_font)

    for source, target in edges:
        _draw_arrow(_edge_point(source, "right"), _edge_point(target, "left"), "#00875A", label="CAN_ASSUME")
    for source, target in blocked:
        _draw_arrow(_edge_point(source, "right"), _edge_point(target, "left"), "#DE350B", dashed=True, label="No trust match")

    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _aws_story(evidence: dict) -> list:
    sections = evidence.get("sections", {})
    records = sections.get("iam_configuration", {}).get("records", {})
    story: list = []

    # --- Identity Inventory ---
    story.append(_section_heading("Identity Inventory"))
    user_rows, group_rows = _aws_identity_inventory(records)
    story.append(_kept_subsection("Users", _compact_table(user_rows, [("User", "User"), ("Groups", "Groups"), ("Direct Policies", "Direct Policies")])))
    story.append(
        _kept_subsection("Groups", _compact_table(group_rows, [("Group", "Group"), ("Members", "Members"), ("Attached Policies", "Attached Policies")]))
    )

    # --- Roles & Access Paths ---
    access_paths_body: list = []
    edges, blocked = _aws_access_paths(records)
    if edges or blocked:
        png_bytes = _render_access_path_png(edges, blocked)
        if png_bytes:
            image_reader = Image.open(BytesIO(png_bytes))
            display_width = min(_CONTENT_WIDTH, image_reader.width)
            display_height = display_width * image_reader.height / image_reader.width
            access_paths_body.append(ReportlabImage(BytesIO(png_bytes), width=display_width, height=display_height))
        access_paths_body.append(
            Paragraph(
                "An arrow is drawn only when both sides agree: a policy grants sts:AssumeRole on the target role, "
                "and that role's trust policy names the source principal. A grant without a matching trust "
                "relationship is shown as blocked, not as a working path.",
                _NOTE_STYLE,
            )
        )
    else:
        access_paths_body.append(Paragraph("No role-assumption relationships were found in the collected policy and trust data.", _NOTE_STYLE))
    # KeepTogether at the section level (not just _kept_subsection's H3
    # level) - the diagram is short enough to always fit fresh on a page,
    # and without this the heading previously landed alone at the very
    # bottom of a page with the diagram itself pushed to the next one.
    story.append(KeepTogether([_section_heading("Roles & Access Paths"), *access_paths_body]))

    # --- Policies ---
    story.append(_section_heading("Policies"))
    story.append(
        Paragraph(
            "Each policy's statements are summarized below; complete policy documents remain in the underlying collection record.",
            _NOTE_STYLE,
        )
    )
    policy_rows = _aws_policy_table_rows(records)
    story.extend(
        _compact_table(
            policy_rows,
            [("Policy", "Policy"), ("Attached To", "Attached To"), ("Summary", "Summary"), ("Patterns", "Patterns")],
            max_rows=MAX_POLICY_ROWS,
        )
    )

    # --- Activity Evidence ---
    # The section heading is kept together with its first subsection (not
    # just appended before it) - otherwise the heading alone can land at
    # the bottom of a page with all its content pushed to the next one.
    last_accessed = sections.get("last_accessed", {})
    la_rows = [
        {
            "Principal": record.get("principal_name"),
            "Type": record.get("principal_type"),
            "Services Observed": ", ".join(s.get("ServiceNamespace", "") for s in record.get("services_last_accessed", [])) or "(none reported)",
        }
        for record in last_accessed.get("records", [])
    ]
    story.append(
        KeepTogether(
            [
                _section_heading("Activity Evidence"),
                Paragraph("Last Accessed", _H3_STYLE),
                *_compact_table(la_rows, [("Principal", "Principal"), ("Type", "Type"), ("Services Observed", "Services Observed")]),
            ]
        )
    )

    cloudtrail = sections.get("cloudtrail", {})
    window = cloudtrail.get("evidence_window", {})
    cloudtrail_body = [Paragraph(f"Region {_esc(cloudtrail.get('region'))}, {_esc(window.get('lookback_days'))}-day lookback window.", _NOTE_STYLE)]
    events = cloudtrail.get("records", [])
    if not events:
        cloudtrail_body.append(Paragraph("No events collected in this window.", _NOTE_STYLE))
    else:
        for event in events[:MAX_RECORD_ROWS]:
            card_lines = [
                f"<b>{_esc(event.get('EventName'))}</b>",
                f"Time: {_esc(event.get('EventTime'))}",
                f"Attributed principal: {_esc(event.get('attributed_principal_arn') or 'unattributed')}",
            ]
            card = Table([[[Paragraph(line, _KV_STYLE) for line in card_lines]]], colWidths=[_CONTENT_WIDTH])
            card.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            cloudtrail_body.append(card)
            cloudtrail_body.append(Spacer(1, 4))
        if len(events) > MAX_RECORD_ROWS:
            cloudtrail_body.append(Paragraph(f"{len(events) - MAX_RECORD_ROWS} additional event(s) retained in the underlying collection record.", _NOTE_STYLE))
    story.append(_kept_subsection("CloudTrail Events", cloudtrail_body))

    # --- Access Analyzer ---
    story.append(_section_heading("Access Analyzer"))
    analyzer = sections.get("access_analyzer", {})
    analyzer_records = analyzer.get("records", {})
    story.extend(
        _compact_table(
            analyzer_records.get("analyzers", []),
            [("Name", "name"), ("Type", "type"), ("Status", "status")],
        )
    )
    finding_count = analyzer.get("counts", {}).get("findings", 0)
    story.append(Paragraph(f"Findings reported by these analyzers: {finding_count}.", _NOTE_STYLE))

    return story


# --- vCenter: presentation-only derivation over already-collected records --

_IMPORTANT_ROLE_NAMES = ("Admin", "NoAccess", "DangerousRole", "ConnectorReaderPlus")
_IMPORTANT_PRIVILEGE_IDS = (
    "Authorization.ModifyPermissions",
    "Authorization.ModifyRoles",
    "Global.Settings",
    "Host.Config.Settings",
    "Sessions.TerminateSession",
)
_IMPORTANT_ASSIGNMENT_ROLES = ("Admin", "ConnectorReaderPlus", "ReadOnly", "DangerousRole", "NoAccess")


def _vcenter_role_summary(roles: dict) -> dict:
    values = list(roles.values())
    system_count = sum(1 for role in values if role.get("system"))
    return {"total": len(values), "system": system_count, "custom": len(values) - system_count}


def _vcenter_important_roles(roles: dict) -> list[dict]:
    by_name = {role["name"]: role for role in roles.values()}
    return [by_name[name] for name in _IMPORTANT_ROLE_NAMES if name in by_name]


def _vcenter_privilege_groups(privileges: dict) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for privilege in privileges.values():
        group = privilege.get("group_name") or "Other"
        counts[group] = counts.get(group, 0) + 1
    return sorted(counts.items(), key=lambda item: -item[1])[:10]


def _vcenter_important_privileges(privileges: dict) -> list[dict]:
    return [privileges[priv_id] for priv_id in _IMPORTANT_PRIVILEGE_IDS if priv_id in privileges]


def _flatten_entity_permissions(entity_permissions: list[dict]) -> tuple[list[dict], list[dict]]:
    direct, inherited = [], []
    for entity in entity_permissions:
        direct.extend(entity.get("direct", []))
        inherited.extend(entity.get("inherited", []))
    return direct, inherited


def _representative_permission_rows(rows: list[dict], limit: int) -> list[dict]:
    """Prioritizes rows whose role matches the same illustrative role names
    highlighted elsewhere in this report (Admin, ConnectorReaderPlus,
    ReadOnly, DangerousRole, NoAccess), then fills any remaining space with
    the next collected rows as they appear - never invents a row, only
    reorders and limits which real rows are shown first."""
    important = [row for row in rows if row.get("role_name") in _IMPORTANT_ASSIGNMENT_ROLES]
    rest = [row for row in rows if row not in important]

    seen: set[tuple] = set()
    ordered = []
    for row in important + rest:
        key = (row.get("principal"), row.get("role_name"), row.get("entity_id"))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(row)
        if len(ordered) >= limit:
            break
    return ordered


def _permission_row_dicts(rows: list[dict], access_label: str) -> list[dict]:
    return [
        {
            "Entity": f"{row.get('entity_type', '')} {row.get('entity_id', '')}".strip(),
            "Principal": row.get("principal"),
            "Role": row.get("role_name"),
            "Access": access_label,
            "Propagate": row.get("propagate"),
        }
        for row in rows
    ]


def _vcenter_entity_names(inventory_records: dict) -> dict[str, str]:
    """entity_id -> display name, from the inventory already collected in
    this same evidence file - used only to make the Access Assignment Map
    readable (a name instead of a bare moref id); falls back to the id
    itself when a name isn't available, never invents one."""
    names: dict[str, str] = {}
    for records in inventory_records.values():
        for record in records:
            entity_id = record.get("id")
            if entity_id:
                names[entity_id] = record.get("name") or entity_id
    return names


def _diverse_direct_rows(direct_rows: list[dict], limit: int) -> list[dict]:
    """One row per important role first (so a role with many holders - e.g.
    several service accounts all holding Admin - can never crowd out the
    single real DangerousRole or NoAccess example), then fills any
    remaining slots with the next collected rows in order. Every row
    returned is a real row from direct_rows; this only reorders and caps
    which ones are shown, and never invents one."""
    by_role: dict[str, dict] = {}
    for row in direct_rows:
        role_name = row.get("role_name")
        if role_name in _IMPORTANT_ASSIGNMENT_ROLES and role_name not in by_role:
            by_role[role_name] = row
    one_per_role = [by_role[name] for name in _IMPORTANT_ASSIGNMENT_ROLES if name in by_role]

    seen = {(row.get("principal"), row.get("role_name"), row.get("entity_id")) for row in one_per_role}
    ordered = list(one_per_role)
    for row in direct_rows:
        if len(ordered) >= limit:
            break
        key = (row.get("principal"), row.get("role_name"), row.get("entity_id"))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(row)
    return ordered[:limit]


def _vcenter_access_assignment_map(direct_rows: list[dict], entity_names: dict[str, str], limit: int) -> list[str]:
    """(principal -> role -> entity) path strings for a handful of real,
    directly-observed assignments, guaranteeing one example per important
    role (Admin, ConnectorReaderPlus, ReadOnly, DangerousRole, NoAccess) so
    a role with many holders can't fill every slot before the others get a
    turn. Every path is a single real (principal, role, entity) fact
    already present in the collected direct-permission data - none is
    constructed or inferred."""
    shown = _diverse_direct_rows(direct_rows, limit)
    paths = []
    for row in shown:
        entity_name = entity_names.get(row.get("entity_id"), row.get("entity_id"))
        paths.append(f"{row.get('principal')} -> {row.get('role_name')} -> {entity_name}")
    return paths


def _access_assignment_map_block(paths: list[str]) -> Table:
    """A compact, bordered card listing each real access path on its own
    line - the presentation-friendly stand-in for a raw permission table,
    for the handful of relationships worth calling out by name."""
    content = [Paragraph(_esc(path), _KV_STYLE) for path in paths] if paths else [Paragraph("No direct assignments collected.", _NOTE_STYLE)]
    table = Table([[content]], colWidths=[_CONTENT_WIDTH])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _vcenter_story(evidence: dict) -> list:
    sections = evidence.get("sections", {})
    story: list = []

    # --- Inventory Overview ---
    story.append(_section_heading("Inventory Overview"))
    inventory = sections.get("inventory", {})
    story.append(
        Paragraph(
            "The collected inventory did not include parent/child relationships for these objects (the REST list "
            "endpoints used here do not return one), so objects are listed by type rather than as a hierarchy - "
            "showing a parent-child tree here would imply structure this collection does not actually have.",
            _NOTE_STYLE,
        )
    )
    for object_type in ("datacenter", "folder", "cluster", "host", "vm", "resource_pool"):
        items = inventory.get("records", {}).get(object_type, [])
        rows = [{"Name": item.get("name") or item.get("id"), "ID": item.get("id")} for item in items]
        story.append(_kept_subsection(object_type.replace("_", " ").title(), _compact_table(rows, [("Name", "Name"), ("ID", "ID")])))

    authorization = sections.get("authorization", {})

    # --- Roles ---
    # The section heading and its summary line are kept together with the
    # Representative roles subsection (not just appended before it) -
    # otherwise the heading and summary alone can land at the bottom of a
    # page with the table pushed to the next one.
    roles = authorization.get("roles", {})
    summary = _vcenter_role_summary(roles)
    important_roles = _vcenter_important_roles(roles)
    story.append(
        KeepTogether(
            [
                _section_heading("Roles"),
                Paragraph(f"{summary['total']} roles collected ({summary['system']} built-in, {summary['custom']} custom).", _KV_STYLE),
                Paragraph("Representative roles", _H3_STYLE),
                *_compact_table(
                    [
                        {"Role": role["name"], "Kind": "Built-in" if role.get("system") else "Custom", "Privileges Granted": len(role.get("privilege_ids", []))}
                        for role in important_roles
                    ],
                    [("Role", "Role"), ("Kind", "Kind"), ("Privileges Granted", "Privileges Granted")],
                ),
            ]
        )
    )
    story.append(Paragraph(f"{summary['total']} roles collected. Complete role inventory retained in the underlying collection record.", _NOTE_STYLE))

    # --- Privileges ---
    story.append(_section_heading("Privileges"))
    privileges = authorization.get("privileges", {})
    story.append(Paragraph(f"{len(privileges)} privileges collected, grouped by the functional area they belong to:", _KV_STYLE))
    groups = _vcenter_privilege_groups(privileges)
    story.extend(_compact_table([{"Group": g, "Privilege Count": c} for g, c in groups], [("Group", "Group"), ("Privilege Count", "Privilege Count")], max_rows=len(groups) or 1))
    important_privileges = _vcenter_important_privileges(privileges)
    story.append(
        _kept_subsection(
            "Representative privileges",
            _compact_table(important_privileges, [("Privilege ID", "privId"), ("Name", "name"), ("Group", "group_name")], max_rows=len(important_privileges) or 1),
        )
    )
    story.append(Paragraph(f"{len(privileges)} privileges collected. Complete privilege inventory retained in the underlying collection record.", _NOTE_STYLE))

    # --- Permission Assignments ---
    story.append(_section_heading("Permission Assignments"))
    entity_permissions = authorization.get("entity_permissions", [])
    direct_rows, inherited_rows = _flatten_entity_permissions(entity_permissions)
    total = len(direct_rows) + len(inherited_rows)
    story.extend(
        _metric_cards(
            [("Direct", len(direct_rows)), ("Inherited", len(inherited_rows)), ("Total", total)],
            per_row=3,
        )
    )

    entity_names = _vcenter_entity_names(inventory.get("records", {}))
    access_paths = _vcenter_access_assignment_map(direct_rows, entity_names, MAX_ACCESS_MAP_ROWS)
    story.append(
        _kept_subsection(
            "Access Assignment Map",
            [
                Paragraph("Representative principal -> role -> entity paths, drawn only from direct assignments actually collected:", _NOTE_STYLE),
                _access_assignment_map_block(access_paths),
            ],
        )
    )

    direct_shown = _representative_permission_rows(direct_rows, MAX_PERMISSION_ROWS)
    story.append(
        _kept_subsection(
            "Direct Permissions (representative)",
            _compact_table(
                _permission_row_dicts(direct_shown, "Direct"),
                [("Entity", "Entity"), ("Principal", "Principal"), ("Role", "Role"), ("Propagate", "Propagate")],
                max_rows=len(direct_shown) or 1,
                note=f"All {len(direct_rows)} direct assignments are retained in the underlying collection record." if len(direct_rows) > len(direct_shown) else None,
            ),
        )
    )
    inherited_shown = _representative_permission_rows(inherited_rows, MAX_PERMISSION_ROWS)
    story.append(
        _kept_subsection(
            "Inherited Permissions (representative)",
            _compact_table(
                _permission_row_dicts(inherited_shown, "Inherited"),
                [("Entity", "Entity"), ("Principal", "Principal"), ("Role", "Role"), ("Propagate", "Propagate")],
                max_rows=len(inherited_shown) or 1,
                note=f"All {len(inherited_rows)} inherited assignments are retained in the underlying collection record." if len(inherited_rows) > len(inherited_shown) else None,
            ),
        )
    )

    return story


# --- page 1: overview ---------------------------------------------------


def _aws_overview_metrics(evidence: dict) -> list[tuple[str, object]]:
    sections = evidence.get("sections", {})
    iam = sections.get("iam_configuration", {}).get("counts", {})
    return [
        ("Users", iam.get("users", 0)),
        ("Groups", iam.get("groups", 0)),
        ("Roles", iam.get("roles", 0)),
        ("Policies", iam.get("policies", 0)),
        ("Last Accessed Principals", sections.get("last_accessed", {}).get("counts", {}).get("principals", 0)),
        ("CloudTrail Events", sections.get("cloudtrail", {}).get("counts", {}).get("events", 0)),
        ("Access Analyzer Findings", sections.get("access_analyzer", {}).get("counts", {}).get("findings", 0)),
    ]


def _vcenter_overview_metrics(evidence: dict) -> list[tuple[str, object]]:
    sections = evidence.get("sections", {})
    inventory_counts = sections.get("inventory", {}).get("counts", {})
    authorization_counts = sections.get("authorization", {}).get("counts", {})
    total_assignments = authorization_counts.get("direct_permissions", 0) + authorization_counts.get("inherited_permissions", 0)
    return [
        ("Inventory Objects", sum(inventory_counts.values())),
        ("Roles", authorization_counts.get("roles", 0)),
        ("Privileges", authorization_counts.get("privileges", 0)),
        ("Permission Assignments", total_assignments),
        ("Direct Permissions", authorization_counts.get("direct_permissions", 0)),
        ("Inherited Permissions", authorization_counts.get("inherited_permissions", 0)),
    ]


def _overview_story(evidence: dict, title: str) -> list:
    provider = evidence.get("provider")
    identity = evidence.get("identity", {})

    extra_lines = [f"<b>{key.replace('_', ' ').title()}:</b> {_esc(value)}" for key, value in identity.items() if value]

    story: list = [
        Paragraph(title, _TITLE_STYLE),
        Paragraph("Read-only record of data collected during this audit", _SUBTITLE_STYLE),
        Paragraph(f"<b>Provider:</b> {_esc(provider)}", _KV_STYLE),
        *_identity_block(evidence, extra_lines),
        Spacer(1, 10),
    ]

    story.append(_section_heading("Collection Overview"))
    if provider == "aws":
        story.extend(_metric_cards(_aws_overview_metrics(evidence)))
        caption = None
    else:
        story.extend(_metric_cards(_vcenter_overview_metrics(evidence)))
        authorization_counts = evidence.get("sections", {}).get("authorization", {}).get("counts", {})
        policy_count = evidence.get("normalized_counts", {}).get("policies", 0)
        caption = (
            f"vCenter's {authorization_counts.get('roles', 0)} roles are represented in Sentinel's normalized model as "
            f"{policy_count} policies/permissions (one per role-to-entity binding) rather than as a separate role count - "
            "the same shared model AWS roles use."
        )
    story.append(Spacer(1, 4))
    story.append(_normalized_model_callout(evidence, caption))

    return story


def _completeness_story(evidence: dict) -> list:
    provider = evidence.get("provider")
    story: list = [
        _section_heading("Evidence Completeness"),
        Paragraph(
            "This document is a human-readable presentation of one audit run's collected data. It is not a security "
            "assessment: no finding, severity, or recommendation appears anywhere in it. Collection status above "
            "reflects the actual outcome of this run, not an assumption of success.",
            _KV_STYLE,
        ),
        Spacer(1, 6),
        Paragraph("Every complete collected record shown in summarized or curated form above is retained in full in the underlying collection record.", _KV_STYLE),
        Spacer(1, 10),
    ]

    if provider == "vcenter":
        authorization_counts = evidence.get("sections", {}).get("authorization", {}).get("counts", {})
        total_assignments = authorization_counts.get("direct_permissions", 0) + authorization_counts.get("inherited_permissions", 0)
        story.append(
            _callout(
                "Provider-Collected vs. Normalized Common Model",
                [
                    f"Provider-collected: {authorization_counts.get('roles', 0)} roles, {authorization_counts.get('privileges', 0)} privileges, "
                    f"{total_assignments} permission assignments.",
                    f"Normalized common model: {evidence.get('normalized_counts', {}).get('policies', 0)} policies and "
                    f"{evidence.get('normalized_counts', {}).get('attachments', 0)} attachments represent every role-to-entity binding above "
                    "(see Collection Overview for how vCenter's roles map into this shared model).",
                    "These describe the same underlying facts at two different layers of Sentinel's pipeline - the normalized model is never the provider's own inventory count.",
                ],
            )
        )
    return story


def render_collection_evidence_pdf(evidence_json_path: Path, output_path: Path) -> Path:
    """Render a Collection Evidence PDF strictly from an already-written
    collection_evidence.json - never recomputes a collected fact, never
    reconnects to any provider. Raises ValueError for an unrecognized
    provider rather than silently rendering an empty or generic document."""
    evidence = json.loads(Path(evidence_json_path).read_text())
    provider = evidence.get("provider")
    title = TITLES.get(provider)
    if title is None:
        raise ValueError(f"Unknown provider in collection evidence: {provider!r}")

    story = _overview_story(evidence, title)
    # No forced page break here for either provider - a dedicated overview
    # page reliably left large blank space beneath the metric cards, since
    # the overview itself is short. Provider data now flows directly under
    # it, and pagination falls wherever the actual content runs out.
    story.append(Spacer(1, 14))
    if provider == "aws":
        story.extend(_aws_story(evidence))
    else:
        story.extend(_vcenter_story(evidence))
    # Evidence Completeness is never forced onto its own page - it flows
    # right after whatever content precedes it, landing on the same page
    # when it fits rather than leaving a near-empty final page.
    story.append(Spacer(1, 14))
    story.extend(_completeness_story(evidence))

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=LETTER,
        topMargin=_PAGE_TOP_MARGIN,
        bottomMargin=_PAGE_BOTTOM_MARGIN,
        leftMargin=_PAGE_SIDE_MARGIN,
        rightMargin=_PAGE_SIDE_MARGIN,
    )
    doc.build(story, canvasmaker=_numbered_canvas_factory(title))
    return output_path
