"""
CALIX MAST Security Assessment PDF Generator.

Generates a CALIX-branded MAST report from the normalized
MASTService assessment.

MobSF is used as the scanning engine, but the generated
deliverable is a CALIX MAST report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


def _safe(value: Any) -> str:
    if value is None:
        return "-"
    return escape(str(value))


def _severity_color(severity: str):
    severity = (severity or "").upper()

    if severity == "HIGH":
        return colors.HexColor("#c62828")

    if severity in {"MEDIUM", "WARNING"}:
        return colors.HexColor("#b26a00")

    if severity == "LOW":
        return colors.HexColor("#2e7d32")

    return colors.HexColor("#52606d")


def _score_label(score: Any) -> str:
    try:
        score = int(score)
    except Exception:
        return "Not Available"

    if score >= 80:
        return "Low Risk"

    if score >= 60:
        return "Moderate Risk"

    if score >= 40:
        return "High Risk"

    return "Critical Risk"


class CalixMastDocTemplate(BaseDocTemplate):

    def __init__(self, filename: str, **kwargs):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=16 * mm,
            rightMargin=16 * mm,
            topMargin=22 * mm,
            bottomMargin=18 * mm,
            **kwargs,
        )

        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="normal",
        )

        self.addPageTemplates(
            [
                PageTemplate(
                    id="calix",
                    frames=frame,
                    onPage=self._draw_page,
                )
            ]
        )

    @staticmethod
    def _draw_page(canvas, doc):
        canvas.saveState()

        width, height = A4

        # Header
        canvas.setFillColor(colors.HexColor("#075eb5"))
        canvas.rect(
            0,
            height - 16 * mm,
            width,
            16 * mm,
            fill=1,
            stroke=0,
        )

        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(
            16 * mm,
            height - 10.5 * mm,
            "CALIX",
        )

        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            width - 16 * mm,
            height - 10.5 * mm,
            "SECURITY INTELLIGENCE PLATFORM | MAST",
        )

        # Footer
        canvas.setStrokeColor(colors.HexColor("#d9e2ec"))
        canvas.line(
            16 * mm,
            11 * mm,
            width - 16 * mm,
            11 * mm,
        )

        canvas.setFillColor(colors.HexColor("#697586"))
        canvas.setFont("Helvetica", 7.5)

        canvas.drawString(
            16 * mm,
            6.5 * mm,
            "CALIX MAST Security Assessment",
        )

        canvas.drawRightString(
            width - 16 * mm,
            6.5 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()


def generate_calix_mast_pdf(
    assessment: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """
    Generate a professional CALIX MAST security assessment PDF.
    """

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()

    title = ParagraphStyle(
        "CalixTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=30,
        textColor=colors.HexColor("#123f6d"),
        spaceAfter=8,
    )

    subtitle = ParagraphStyle(
        "CalixSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=16,
        textColor=colors.HexColor("#667085"),
        spaceAfter=16,
    )

    section = ParagraphStyle(
        "CalixSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#123f6d"),
        spaceBefore=12,
        spaceAfter=9,
    )

    body = ParagraphStyle(
        "CalixBody",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#344054"),
        spaceAfter=5,
    )

    small = ParagraphStyle(
        "CalixSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#667085"),
    )

    finding_title = ParagraphStyle(
        "FindingTitle",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#173f67"),
    )

    metric_value = ParagraphStyle(
        "MetricValue",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#123f6d"),
        alignment=TA_CENTER,
    )

    metric_label = ParagraphStyle(
        "MetricLabel",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#667085"),
        alignment=TA_CENTER,
    )

    story = []

    application = assessment.get("application") or {}
    security = assessment.get("security") or {}
    statistics = assessment.get("statistics") or {}
    findings = assessment.get("findings") or []
    permissions = assessment.get("permissions") or {}
    trackers = assessment.get("trackers") or {}
    domains = assessment.get("domains") or {}
    secrets = assessment.get("secrets") or {}
    urls = assessment.get("urls") or {}

    app_name = (
        application.get("app_name")
        or application.get("file_name")
        or "Mobile Application"
    )

    generated = datetime.now(timezone.utc).astimezone()
    generated_text = generated.strftime(
        "%d %B %Y, %I:%M %p %Z"
    )

    # --------------------------------------------------------
    # COVER / TITLE
    # --------------------------------------------------------

    story.append(Spacer(1, 12 * mm))

    story.append(
        Paragraph(
            "CALIX MAST",
            title,
        )
    )

    story.append(
        Paragraph(
            "Mobile Application Security Assessment Report",
            ParagraphStyle(
                "ReportTitle",
                parent=title,
                fontSize=19,
                leading=24,
                spaceAfter=10,
            ),
        )
    )

    story.append(
        Paragraph(
            "Android and iOS application security assessment "
            "powered by the Calix Security Intelligence Platform.",
            subtitle,
        )
    )

    app_table = Table(
        [
            [
                Paragraph("<b>Application</b>", body),
                Paragraph(_safe(app_name), body),
            ],
            [
                Paragraph("<b>File</b>", body),
                Paragraph(
                    _safe(application.get("file_name")),
                    body,
                ),
            ],
            [
                Paragraph("<b>Type</b>", body),
                Paragraph(
                    _safe(application.get("app_type")).upper(),
                    body,
                ),
            ],
            [
                Paragraph("<b>Package / Bundle ID</b>", body),
                Paragraph(
                    _safe(application.get("package_name")),
                    body,
                ),
            ],
            [
                Paragraph("<b>Version</b>", body),
                Paragraph(
                    _safe(application.get("version_name")),
                    body,
                ),
            ],
            [
                Paragraph("<b>SHA-256</b>", body),
                Paragraph(
                    _safe(application.get("sha256")),
                    small,
                ),
            ],
            [
                Paragraph("<b>Main Activity</b>", body),
                Paragraph(
                    _safe(application.get("main_activity")),
                    small,
                ),
            ],
            [
                Paragraph("<b>Assessment Date</b>", body),
                Paragraph(generated_text, body),
            ],
        ],
        colWidths=[48 * mm, 125 * mm],
    )

    app_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#f4f7fb"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    colors.HexColor("#d8e1eb"),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#e5eaf0"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(app_table)
    story.append(Spacer(1, 9 * mm))

    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Assessment Summary",
            section,
        )
    )

    score = security.get("security_score")
    score_text = "-" if score is None else f"{score}/100"

    metrics = [
        ("Security Score", score_text),
        ("High", security.get("high", 0)),
        ("Medium", security.get("warning", 0)),
        ("Info", security.get("info", 0)),
        ("Findings", statistics.get("finding_count", 0)),
    ]

    metric_cells = []

    for label, value in metrics:
        metric_cells.append(
            [
                Paragraph(str(value), metric_value),
                Paragraph(_safe(label), metric_label),
            ]
        )

    metric_table = Table(
        [metric_cells],
        colWidths=[34 * mm] * len(metric_cells),
    )

    metric_table.setStyle(
        TableStyle(
            [
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    colors.HexColor("#d8e1eb"),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#e5eaf0"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.white,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    story.append(metric_table)

    risk_text = _score_label(score)

    story.append(
        Spacer(1, 4 * mm)
    )

    story.append(
        Paragraph(
            f"<b>Overall Risk Rating:</b> {risk_text}",
            body,
        )
    )

    # --------------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Executive Summary",
            section,
        )
    )

    story.append(
        Paragraph(
            f"The MAST assessment identified "
            f"<b>{statistics.get('finding_count', 0)}</b> "
            f"security findings for <b>{_safe(app_name)}</b>. "
            f"The application security score is "
            f"<b>{score_text}</b>, corresponding to "
            f"<b>{_safe(risk_text)}</b>.",
            body,
        )
    )

    story.append(
        Paragraph(
            f"The assessment identified "
            f"<b>{security.get('high', 0)}</b> high-severity, "
            f"<b>{security.get('warning', 0)}</b> medium-severity, "
            f"and <b>{security.get('info', 0)}</b> informational "
            f"findings.",
            body,
        )
    )

    story.append(
        Paragraph(
            f"The application also contains "
            f"<b>{statistics.get('dangerous_permission_count', 0)}</b> "
            f"dangerous permissions, "
            f"<b>{statistics.get('tracker_count', 0)}</b> trackers, "
            f"<b>{statistics.get('domain_count', 0)}</b> domains, "
            f"<b>{statistics.get('secret_count', 0)}</b> potential "
            f"secrets, and "
            f"<b>{statistics.get('url_count', 0)}</b> extracted URLs.",
            body,
        )
    )

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            section,
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were returned by the assessment.",
                body,
            )
        )

    for index, finding in enumerate(findings, start=1):

        severity = (
            finding.get("severity")
            or "INFO"
        ).upper()

        severity_style = ParagraphStyle(
            f"Severity{index}",
            parent=body,
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=_severity_color(severity),
        )

        finding_header = Table(
            [
                [
                    Paragraph(
                        _safe(severity),
                        severity_style,
                    ),
                    Paragraph(
                        f"{index}. "
                        f"{_safe(finding.get('title'))}",
                        finding_title,
                    ),
                ]
            ],
            colWidths=[24 * mm, 149 * mm],
        )

        finding_header.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        colors.HexColor("#f5f7fa"),
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#d8e1eb"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        story.append(
            KeepTogether(
                [
                    finding_header,
                    Spacer(1, 2 * mm),
                    Paragraph(
                        "<b>Description</b>",
                        small,
                    ),
                    Paragraph(
                        _safe(finding.get("description")),
                        body,
                    ),
                    Paragraph(
                        "<b>Remediation</b>",
                        small,
                    ),
                    Paragraph(
                        _safe(
                            finding.get("remediation")
                            or "Remediation guidance was not provided."
                        ),
                        body,
                    ),
                    Paragraph(
                        f"<b>Section:</b> "
                        f"{_safe(finding.get('section'))}",
                        small,
                    ),
                    Spacer(1, 4 * mm),
                ]
            )
        )

    # --------------------------------------------------------
    # PERMISSIONS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Dangerous Permissions",
            section,
        )
    )

    permission_items = permissions.get("items") or []

    if permission_items:
        rows = [
            [
                Paragraph("<b>Permission</b>", body),
                Paragraph("<b>Status</b>", body),
                Paragraph("<b>Description</b>", body),
            ]
        ]

        for item in permission_items:
            rows.append(
                [
                    Paragraph(
                        _safe(item.get("name")),
                        small,
                    ),
                    Paragraph(
                        _safe(item.get("status")),
                        small,
                    ),
                    Paragraph(
                        _safe(item.get("description")),
                        small,
                    ),
                ]
            )

        table = Table(
            rows,
            colWidths=[
                52 * mm,
                25 * mm,
                96 * mm,
            ],
            repeatRows=1,
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#edf4fb"),
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#d8e1eb"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(table)
    else:
        story.append(
            Paragraph(
                "No dangerous permissions were reported.",
                body,
            )
        )

    # --------------------------------------------------------
    # ADDITIONAL STATISTICS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Application Security Indicators",
            section,
        )
    )

    indicator_rows = [
        ["Indicator", "Count"],
        ["Dangerous Permissions",
         statistics.get("dangerous_permission_count", 0)],
        ["Trackers",
         statistics.get("tracker_count", 0)],
        ["Domains",
         statistics.get("domain_count", 0)],
        ["Potential Secrets",
         statistics.get("secret_count", 0)],
        ["Extracted URLs",
         statistics.get("url_count", 0)],
    ]

    indicator_table = Table(
        indicator_rows,
        colWidths=[110 * mm, 63 * mm],
        repeatRows=1,
    )

    indicator_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#edf4fb"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#d8e1eb"),
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8.5,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    story.append(indicator_table)

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Recommendations",
            section,
        )
    )

    recommendations = [
        "Prioritize remediation of all HIGH severity findings.",
        "Review Android manifest activities, task affinity, and launch modes.",
        "Review all dangerous permissions and remove unnecessary permissions.",
        "Investigate potential hardcoded secrets and sensitive material identified during static analysis.",
        "Review third-party SDKs and trackers for security and privacy requirements.",
        "Validate all externally referenced domains and network endpoints.",
        "Maintain current Android/iOS platform security requirements and SDK targets.",
        "Perform a follow-up MAST assessment after remediation.",
    ]

    for recommendation in recommendations:
        story.append(
            Paragraph(
                f"• {_safe(recommendation)}",
                body,
            )
        )

    # --------------------------------------------------------
    # FOOTNOTE
    # --------------------------------------------------------

    story.append(
        Spacer(1, 8 * mm)
    )

    story.append(
        Paragraph(
            "<b>Report Classification:</b> Internal Security Assessment",
            small,
        )
    )

    story.append(
        Paragraph(
            "This report was generated by the CALIX Security "
            "Intelligence Platform MAST service. MobSF is used "
            "as the underlying mobile security analysis engine; "
            "this document represents the normalized CALIX "
            "security assessment output.",
            small,
        )
    )

    doc = CalixMastDocTemplate(
        str(output),
        title=f"CALIX MAST - {app_name}",
        author="CALIX Security Intelligence Platform",
        subject="Mobile Application Security Assessment",
    )

    doc.build(story)

    return output
