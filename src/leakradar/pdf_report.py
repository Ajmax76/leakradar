import json
import os
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from leakradar.bola_matrix import Finding
from leakradar.redactor import Redactor


class PDFReportGenerator:
    """
    Generates professional executive PDF reports for security audits using ReportLab.
    """

    @classmethod
    def generate(
        cls,
        findings: List[Finding],
        target_name: str,
        output_path: str,
        client_name: str = "Client Audit",
        custom_tokens: Optional[List[str]] = None,
    ):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=15,
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=12,
            spaceAfter=8,
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )

        code_style = ParagraphStyle(
            "CodeText",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
            backColor=colors.HexColor("#F8FAFC"),
            borderColor=colors.HexColor("#E2E8F0"),
            borderWidth=0.5,
            borderPadding=4,
            spaceAfter=6,
        )

        story = []

        # Document Header
        story.append(Paragraph(f"LeakRadar Security Audit Report", title_style))
        story.append(Paragraph(f"Target System: <b>{target_name}</b> | Client: <b>{client_name}</b>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=15))

        # Executive Summary
        story.append(Paragraph("Executive Summary", h2_style))
        high_count = sum(1 for f in findings if f.confidence == "high")
        med_count = sum(1 for f in findings if f.confidence == "medium")
        total_count = len(findings)

        summary_text = (
            f"LeakRadar completed an automated Broken Object Level Authorization (BOLA/IDOR) scan for <b>{target_name}</b>. "
            f"A total of <b>{total_count}</b> BOLA vulnerabilities were identified (<b>{high_count} High Confidence</b>, "
            f"<b>{med_count} Medium Confidence</b>)."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))

        # Summary Table
        sum_table_data = [
            [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style)],
            [Paragraph("Target System", body_style), Paragraph(target_name, body_style)],
            [Paragraph("Total Findings", body_style), Paragraph(str(total_count), body_style)],
            [Paragraph("High Confidence BOLA", body_style), Paragraph(str(high_count), body_style)],
            [Paragraph("Medium Confidence BOLA", body_style), Paragraph(str(med_count), body_style)],
        ]
        sum_table = Table(sum_table_data, colWidths=[180, 360])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(sum_table)
        story.append(Spacer(1, 15))

        if not findings:
            story.append(Paragraph("No BOLA vulnerabilities were detected during this scan.", body_style))
        else:
            story.append(Paragraph("Detailed Vulnerability Analysis", h2_style))

            for idx, finding in enumerate(findings, 1):
                story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

                badge_color = "#DC2626" if finding.confidence == "high" else "#D97706"
                finding_title = f"Finding #{idx}: {finding.seed.endpoint_template} [{finding.confidence.upper()}]"
                
                title_p_style = ParagraphStyle(
                    f"FTitle_{idx}",
                    parent=h2_style,
                    fontSize=11,
                    leading=14,
                    textColor=colors.HexColor(badge_color),
                )
                story.append(Paragraph(finding_title, title_p_style))
                story.append(Spacer(1, 5))

                # Finding Meta
                meta_text = (
                    f"<b>Method:</b> {finding.probe_method} | <b>Status Code:</b> {finding.probe_status_code} | "
                    f"<b>Field Overlap:</b> {finding.overlap_score * 100:.1f}%<br/>"
                    f"<b>CVSS:</b> {finding.cvss_suggestion}<br/>"
                    f"<b>CWE:</b> {finding.cwe_suggestion}"
                )
                story.append(Paragraph(meta_text, body_style))
                story.append(Spacer(1, 8))

                # Evidence Table
                ev_table_data = [[
                    Paragraph("<b>Field</b>", body_style),
                    Paragraph("<b>Type</b>", body_style),
                    Paragraph("<b>Description</b>", body_style)
                ]]
                
                if finding.evidence_fields:
                    for ev in finding.evidence_fields:
                        ev_field = Redactor.redact_string(str(ev.get("field", "N/A")), custom_tokens)
                        ev_type = str(ev.get("type", "Signal"))
                        ev_desc = Redactor.redact_string(str(ev.get("description", "")), custom_tokens)
                        ev_table_data.append([
                            Paragraph(f"<code>{ev_field}</code>", body_style),
                            Paragraph(ev_type, body_style),
                            Paragraph(ev_desc, body_style),
                        ])
                else:
                    ev_table_data.append([
                        Paragraph("<code>$</code>", body_style),
                        Paragraph("Data Overlap", body_style),
                        Paragraph(f"User B probe matched {finding.overlap_score * 100:.1f}% of User A fields.", body_style),
                    ])

                ev_table = Table(ev_table_data, colWidths=[120, 120, 300])
                ev_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(ev_table)
                story.append(Spacer(1, 8))

                # cURL PoC
                story.append(Paragraph("<b>Reproduction Command:</b>", body_style))
                curl_clean = Redactor.redact_string(finding.to_curl(), custom_tokens)
                story.append(Paragraph(curl_clean.replace("\n", "<br/>"), code_style))
                story.append(Spacer(1, 10))

        # Remediation Section
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=10))
        story.append(Paragraph("Remediation Recommendations", h2_style))
        remediation_text = (
            "1. Enforce strict object-level access controls at the data layer for all API endpoints.<br/>"
            "2. Ensure authorization decisions evaluate the requesting user's identity against the requested record ID.<br/>"
            "3. Use cryptographically secure random identifiers (UUID v4) instead of sequential integers.<br/>"
            "4. Perform continuous automated API vulnerability testing using tools like LeakRadar."
        )
        story.append(Paragraph(remediation_text, body_style))

        doc.build(story)
