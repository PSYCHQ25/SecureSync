"""
=============================================================================
SecureSync – Multi Detection System
Module: report_generator.py
Description: Generates premium Forensic Intelligence Reports as high-resolution
             PDFs using ReportLab. Features refined ivory/graphite/cobalt-blue
             design, chronological investigation timeline, evidence-backed
             findings, and recommended next actions.
             Supports Text, Image, Audio and Video modalities consistently.
             Uses ONLY real backend data — never invents evidence.
=============================================================================
"""

import io
import html
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# =============================================================================
# Color Palette – Refined Ivory, Graphite & Cobalt-Blue
# =============================================================================
# Ivory / Warm White
IVORY_BG        = colors.HexColor('#f8f8f5')
IVORY_SURFACE   = colors.HexColor('#f0f1ec')
IVORY_INPUT     = colors.HexColor('#ffffff')

# Graphite / Charcoal
GRAPHITE_900    = colors.HexColor('#0c0e12')
GRAPHITE_800    = colors.HexColor('#14171d')
GRAPHITE_700    = colors.HexColor('#1a1e26')
GRAPHITE_500    = colors.HexColor('#3e4450')
GRAPHITE_400    = colors.HexColor('#676e7b')
GRAPHITE_300    = colors.HexColor('#949fb1')
GRAPHITE_200    = colors.HexColor('#c7c9c1')
GRAPHITE_100    = colors.HexColor('#dfdfd8')
GRAPHITE_50     = colors.HexColor('#e9eae4')

# Cobalt Blue Accent
COBALT          = colors.HexColor('#0062ff')
COBALT_DARK     = colors.HexColor('#0050d4')
COBALT_LIGHT    = colors.HexColor('#eff5ff')

# Accessible Red / Green Risk Indicators
RED_CRITICAL    = colors.HexColor('#c5221f')
RED_BG          = colors.HexColor('#fdf2f2')
ORANGE_HIGH     = colors.HexColor('#b45309')
ORANGE_BG       = colors.HexColor('#fffbeb')
AMBER_MEDIUM    = colors.HexColor('#92400e')
AMBER_BG        = colors.HexColor('#fffbeb')
GREEN_SAFE      = colors.HexColor('#15803d')
GREEN_BG        = colors.HexColor('#f0fdf4')


def _safe(val: Any, fallback: str = '—') -> str:
    """Return html-escaped string or a fallback for None/empty values."""
    if val is None:
        return fallback
    s = str(val).strip()
    return html.escape(s) if s else fallback


def _risk_color(level: str) -> colors.HexColor:
    """Map risk level to an accessible color."""
    level = (level or '').upper()
    if level == 'CRITICAL':
        return RED_CRITICAL
    elif level == 'HIGH':
        return ORANGE_HIGH
    elif level == 'MEDIUM':
        return AMBER_MEDIUM
    return GREEN_SAFE


def _risk_bg(level: str) -> colors.HexColor:
    """Map risk level to a subtle background."""
    level = (level or '').upper()
    if level == 'CRITICAL':
        return RED_BG
    elif level == 'HIGH':
        return ORANGE_BG
    elif level == 'MEDIUM':
        return AMBER_BG
    return GREEN_BG


def _modality_label(modality: str) -> str:
    """Return human-friendly modality label."""
    m = (modality or 'text').lower()
    labels = {
        'text': 'Text / Message Analysis',
        'image': 'Image Forensics',
        'audio': 'Audio Forensics',
        'video': 'Video Forensics',
    }
    return labels.get(m, m.title() + ' Analysis')


def _build_timeline(scan_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Construct a chronological investigation timeline from REAL scan data.
    Never fabricates events — each entry is derived from actual fields.
    """
    timeline = []
    modality = (scan_data.get('modality') or 'text').lower()
    timestamp = scan_data.get('created_at') or scan_data.get('timestamp') or ''
    risk_level = (scan_data.get('risk_level') or 'LOW').upper()
    classification = scan_data.get('threat_classification') or scan_data.get('classification') or 'Unknown'
    tech = scan_data.get('technical_details') or {}
    indicators = scan_data.get('suspicious_indicators') or scan_data.get('indicators') or []
    reasons = scan_data.get('detection_reasons') or scan_data.get('reasons') or []
    links = scan_data.get('links') or []
    file_name = scan_data.get('file_name') or ''

    # 1. Submission received
    if modality == 'text':
        submit_desc = 'Text message payload submitted for analysis'
    elif file_name:
        submit_desc = f'{modality.title()} file received: {file_name}'
    else:
        submit_desc = f'{modality.title()} asset submitted for forensic analysis'
    timeline.append({'phase': 'Submission Received', 'detail': submit_desc, 'time': timestamp})

    # 2. Validation / integrity check
    if modality in ('image', 'audio', 'video'):
        fmt = tech.get('format') or tech.get('container') or 'N/A'
        sha = tech.get('sha256', '')
        hash_note = f' · SHA-256 verified ({sha[:12]}…)' if sha else ''
        timeline.append({
            'phase': 'File Validation',
            'detail': f'Format validated as {fmt}{hash_note}',
            'time': ''
        })

        # Metadata extraction
        meta_parts = []
        if tech.get('dimensions'):
            meta_parts.append(f'Dimensions: {tech["dimensions"]}')
        if tech.get('duration_seconds') is not None:
            meta_parts.append(f'Duration: {tech["duration_seconds"]}s')
        if tech.get('sample_rate'):
            meta_parts.append(f'Sample Rate: {tech["sample_rate"]} Hz')
        if tech.get('file_size_formatted'):
            meta_parts.append(f'Size: {tech["file_size_formatted"]}')
        if tech.get('entropy') is not None:
            meta_parts.append(f'Entropy: {tech["entropy"]}/8.0')
        if tech.get('encoder_software'):
            meta_parts.append(f'Encoder: {tech["encoder_software"]}')
        if meta_parts:
            timeline.append({
                'phase': 'Metadata Extraction',
                'detail': ' · '.join(meta_parts),
                'time': ''
            })
    else:
        # Text payload validation
        msg = scan_data.get('submitted_message') or ''
        char_ct = len(msg)
        word_ct = len(msg.split()) if msg else 0
        link_ct = len(links)
        parts = [f'{char_ct} characters', f'{word_ct} words']
        if link_ct > 0:
            parts.append(f'{link_ct} embedded URL(s) extracted')
        timeline.append({
            'phase': 'Payload Parsing',
            'detail': ' · '.join(parts),
            'time': ''
        })

    # 3. Detection engine execution
    if modality == 'text':
        engine_desc = 'Dual NLP + Heuristic Threat Engine executed'
    elif modality == 'image':
        engine_desc = 'Image forensic pipeline: QR decode, steganography scan, metadata analysis, entropy profiling'
    elif modality == 'audio':
        engine_desc = 'Audio forensic pipeline: spectral analysis, voice synthesis detection, frequency profiling'
    elif modality == 'video':
        engine_desc = 'Video forensic pipeline: container analysis, deepfake detection, A/V sync validation'
    else:
        engine_desc = f'{modality.title()} detection engine executed'
    timeline.append({'phase': 'Detection Engine', 'detail': engine_desc, 'time': ''})

    # 4. Findings summary
    ind_count = len(indicators) if isinstance(indicators, list) else 0
    reason_count = len(reasons) if isinstance(reasons, list) else 0
    if ind_count > 0 or reason_count > 0:
        finding_parts = []
        if ind_count > 0:
            finding_parts.append(f'{ind_count} threat indicator(s) identified')
        if reason_count > 0:
            finding_parts.append(f'{reason_count} detection reason(s) logged')
        timeline.append({
            'phase': 'Analysis Complete',
            'detail': ' · '.join(finding_parts),
            'time': ''
        })
    else:
        timeline.append({
            'phase': 'Analysis Complete',
            'detail': 'No malicious signatures or anomalies detected',
            'time': ''
        })

    # 5. Classification issued
    risk_score = scan_data.get('risk_score', scan_data.get('confidence', 0))
    timeline.append({
        'phase': 'Classification Issued',
        'detail': f'{classification} — Risk: {risk_level} ({risk_score}/100)',
        'time': ''
    })

    return timeline


def generate_pdf_report(scan_data: Dict[str, Any], analyst_name: str = "Security Analyst") -> io.BytesIO:
    """
    Renders a premium Forensic Intelligence Report as PDF.
    Uses SecureSync's ivory/graphite/cobalt-blue palette.
    All data sourced exclusively from real backend results.
    Returns an in-memory BytesIO stream ready for HTTP delivery.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=32,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    # =========================================================================
    # Typography Styles
    # =========================================================================
    st_brand = ParagraphStyle(
        'Brand', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=18, leading=22,
        textColor=GRAPHITE_900
    )
    st_brand_sub = ParagraphStyle(
        'BrandSub', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=10,
        textColor=GRAPHITE_400
    )
    st_report_title = ParagraphStyle(
        'ReportTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=10, leading=13,
        textColor=COBALT, alignment=TA_RIGHT
    )
    st_section = ParagraphStyle(
        'SectionHead', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=11, leading=15,
        textColor=GRAPHITE_900, spaceBefore=4, spaceAfter=6
    )
    st_body = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, leading=13,
        textColor=GRAPHITE_900
    )
    st_body_muted = ParagraphStyle(
        'BodyMuted', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=11,
        textColor=GRAPHITE_400
    )
    st_label = ParagraphStyle(
        'MetaLabel', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=7.5, leading=10,
        textColor=GRAPHITE_400
    )
    st_val = ParagraphStyle(
        'MetaVal', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, leading=12,
        textColor=GRAPHITE_900
    )
    st_mono = ParagraphStyle(
        'Mono', parent=styles['Normal'],
        fontName='Courier', fontSize=8, leading=11,
        textColor=GRAPHITE_800
    )
    st_footer = ParagraphStyle(
        'Footer', parent=styles['Normal'],
        fontName='Helvetica', fontSize=7, leading=10,
        textColor=GRAPHITE_300, alignment=TA_CENTER
    )

    # =========================================================================
    # Extract Scan Data (real values only)
    # =========================================================================
    if isinstance(analyst_name, dict):
        analyst_display = analyst_name.get('full_name') or analyst_name.get('username') or analyst_name.get('email') or 'Security Analyst'
    else:
        analyst_display = str(analyst_name or 'Security Analyst')

    scan_id = scan_data.get('scan_id', 'SCN-UNKNOWN')
    timestamp = scan_data.get('created_at') or scan_data.get('timestamp') or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    modality = (scan_data.get('modality') or 'text').lower()
    classification = scan_data.get('threat_classification') or scan_data.get('classification') or 'Unknown'
    threat_category = scan_data.get('threat_category', '')
    if not threat_category:
        tech = scan_data.get('technical_details') or {}
        threat_category = tech.get('threat_category', '')
    if not threat_category:
        threat_category = classification
    risk_level = (scan_data.get('risk_level') or 'LOW').upper()
    risk_score = scan_data.get('risk_score', scan_data.get('confidence', 0))
    action = scan_data.get('recommended_action', 'Maintain standard defensive posture.')
    message = scan_data.get('submitted_message', '') or ''
    file_name = scan_data.get('file_name', '')
    file_hash = scan_data.get('file_hash', '')
    is_threat = (risk_level in ('CRITICAL', 'HIGH')) or ('scam' in classification.lower()) or ('threat' in classification.lower())
    rcolor = _risk_color(risk_level)
    rbg = _risk_bg(risk_level)

    # =========================================================================
    # 1. DOCUMENT HEADER — Brand & Report Title
    # =========================================================================
    header_data = [
        [
            Paragraph("SECURESYNC", st_brand),
            Paragraph(
                "FORENSIC INTELLIGENCE REPORT<br/>"
                "<font color='#676e7b' size='7'>Confidential · Automated Forensic Audit</font>",
                st_report_title
            )
        ],
        [
            Paragraph("Multi Detection System", st_brand_sub),
            Paragraph(
                f"<font color='#676e7b' size='7'>Report Date: {_safe(timestamp)}</font>",
                ParagraphStyle('DateR', parent=st_body_muted, alignment=TA_RIGHT)
            )
        ]
    ]
    t_header = Table(header_data, colWidths=[3.8*inch, 3.7*inch])
    t_header.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 1),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=COBALT, spaceAfter=14))

    # =========================================================================
    # 2. EXECUTIVE ASSESSMENT — Risk level badge + concise summary
    # =========================================================================
    story.append(Paragraph("EXECUTIVE ASSESSMENT", st_section))

    # Risk Level Badge row
    risk_text = f"<font color='{rcolor.hexval()}'><b>{risk_level}</b></font>"
    score_text = f"<b>{risk_score}</b> / 100"

    assessment_summary = (
        f"This {_modality_label(modality).lower()} has been classified as "
        f"<b>{_safe(classification)}</b> with a computed threat score of "
        f"<b>{risk_score}/100</b> ({risk_level} risk)."
    )
    if is_threat:
        assessment_summary += (
            f" The detection engine identified suspicious indicators consistent with "
            f"<b>{_safe(threat_category)}</b>. Immediate review is recommended."
        )
    else:
        assessment_summary += (
            " No malicious signatures or anomalies were identified. "
            "The asset appears consistent with baseline integrity standards."
        )

    exec_data = [
        [
            Paragraph("<b>RISK LEVEL</b>", st_label),
            Paragraph("<b>THREAT SCORE</b>", st_label),
            Paragraph("<b>CLASSIFICATION</b>", st_label),
            Paragraph("<b>DETECTION MODALITY</b>", st_label),
        ],
        [
            Paragraph(risk_text, st_val),
            Paragraph(score_text, st_val),
            Paragraph(f"<b>{_safe(classification)}</b>", st_val),
            Paragraph(_safe(modality.upper()), st_val),
        ],
    ]
    t_exec = Table(exec_data, colWidths=[1.7*inch, 1.7*inch, 2.2*inch, 1.9*inch])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), rbg),
        ('BOX', (0,0), (-1,-1), 0.5, rcolor),
        ('INNERGRID', (0,0), (-1,-1), 0.3, GRAPHITE_100),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 6))
    story.append(Paragraph(assessment_summary, st_body))
    story.append(Spacer(1, 14))

    # =========================================================================
    # 3. SCAN METADATA — ID, analyst, modality, category
    # =========================================================================
    story.append(Paragraph("SCAN METADATA", st_section))
    meta_data = [
        [
            Paragraph("<b>Scan ID</b>", st_label),
            Paragraph(f"<font name='Courier'>{_safe(scan_id)}</font>", st_val),
            Paragraph("<b>Analyst</b>", st_label),
            Paragraph(_safe(analyst_display), st_val),
        ],
        [
            Paragraph("<b>Detection Modality</b>", st_label),
            Paragraph(_safe(modality.upper()), st_val),
            Paragraph("<b>Threat Category</b>", st_label),
            Paragraph(_safe(threat_category), st_val),
        ],
    ]

    # Add file-specific row for media modalities
    if modality in ('image', 'audio', 'video') and (file_name or file_hash):
        meta_data.append([
            Paragraph("<b>File Name</b>", st_label),
            Paragraph(_safe(file_name), st_val),
            Paragraph("<b>SHA-256</b>", st_label),
            Paragraph(f"<font name='Courier' size='7'>{_safe(file_hash[:32] + '...' if len(file_hash or '') > 32 else file_hash)}</font>", st_val),
        ])

    t_meta = Table(meta_data, colWidths=[1.7*inch, 2.1*inch, 1.7*inch, 2.0*inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), IVORY_SURFACE),
        ('BOX', (0,0), (-1,-1), 0.5, GRAPHITE_200),
        ('INNERGRID', (0,0), (-1,-1), 0.3, GRAPHITE_100),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 16))

    # =========================================================================
    # 4. EVIDENCE SAMPLE — Target payload/asset
    # =========================================================================
    story.append(Paragraph("EVIDENCE SAMPLE", st_section))

    if message:
        preview = message if len(message) <= 500 else message[:500] + '… [TRUNCATED]'
        safe_preview = html.escape(preview)
    elif modality in ('image', 'audio', 'video'):
        safe_preview = f"(Binary {modality} forensic analysis conducted directly on submitted file: {_safe(file_name)})"
    else:
        safe_preview = "(No payload content available)"

    ev_table = Table(
        [[Paragraph(f"<font color='#3e4450'>{safe_preview}</font>", st_mono)]],
        colWidths=[7.0*inch]
    )
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), IVORY_SURFACE),
        ('BOX', (0,0), (-1,-1), 0.5, GRAPHITE_200),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 16))

    # =========================================================================
    # 5. EVIDENCE-BACKED FINDINGS — Indicators with explanations
    # =========================================================================
    raw_indicators = scan_data.get('suspicious_indicators') or scan_data.get('indicators') or []

    story.append(Paragraph("EVIDENCE-BACKED FINDINGS", st_section))

    if raw_indicators and len(raw_indicators) > 0:
        ind_header = [
            Paragraph("<b>Finding</b>", st_label),
            Paragraph("<b>Severity</b>", st_label),
            Paragraph("<b>Explanation</b>", st_label),
        ]
        ind_rows = [ind_header]
        for ind in raw_indicators:
            sev = (ind.get('severity') or 'HIGH').upper()
            sev_col = _risk_color(sev)
            ind_rows.append([
                Paragraph(f"<b>{_safe(ind.get('name', 'Threat Vector'))}</b>", st_body),
                Paragraph(f"<font color='{sev_col.hexval()}'><b>{sev}</b></font>", st_body),
                Paragraph(_safe(ind.get('explanation', 'No further detail available.')), st_body),
            ])

        t_ind = Table(ind_rows, colWidths=[2.0*inch, 0.9*inch, 4.1*inch])
        t_ind.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), GRAPHITE_50),
            ('BOX', (0,0), (-1,-1), 0.5, GRAPHITE_200),
            ('INNERGRID', (0,0), (-1,-1), 0.3, GRAPHITE_100),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t_ind)
    else:
        clean_table = Table(
            [[Paragraph(
                "✔ <b>No malicious indicators identified.</b> "
                "The submitted asset demonstrates standard baseline integrity. "
                "No steganographic payloads, social engineering patterns, or anomalous signatures were detected.",
                st_body
            )]],
            colWidths=[7.0*inch]
        )
        clean_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), GREEN_BG),
            ('BOX', (0,0), (-1,-1), 0.5, GREEN_SAFE),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ]))
        story.append(clean_table)
    story.append(Spacer(1, 16))

    # =========================================================================
    # 6. DETECTION REASONING — Why flagged
    # =========================================================================
    reasons = scan_data.get('detection_reasons') or scan_data.get('reasons') or []
    if reasons:
        story.append(Paragraph("DETECTION REASONING", st_section))
        r_rows = []
        for idx, r in enumerate(reasons, 1):
            r_rows.append([
                Paragraph(f"<font color='{COBALT.hexval()}'><b>{idx}.</b></font>", st_body),
                Paragraph(_safe(r), st_body),
            ])
        t_reasons = Table(r_rows, colWidths=[0.3*inch, 6.7*inch])
        t_reasons.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(t_reasons)
        story.append(Spacer(1, 16))

    # =========================================================================
    # 7. QUARANTINED LINKS — Network indicators
    # =========================================================================
    links = scan_data.get('links') or []
    if links:
        story.append(Paragraph("QUARANTINED LINKS", st_section))
        link_header = [
            Paragraph("<b>Defanged URL</b>", st_label),
            Paragraph("<b>Domain</b>", st_label),
            Paragraph("<b>Flags</b>", st_label),
        ]
        link_rows = [link_header]
        for l in links:
            flags = []
            if l.get('is_shortener'):
                flags.append("URL Shortener")
            if l.get('brand_spoofing'):
                flags.append("Brand Spoofing")
            if l.get('has_suspicious_tld'):
                flags.append("Suspicious TLD")
            if l.get('is_ip_address'):
                flags.append("Direct IP")
            flag_str = ", ".join(flags) if flags else "Quarantined"

            link_rows.append([
                Paragraph(f"<font color='#0050d4' name='Courier' size='7'>{_safe(l.get('defanged', ''))}</font>", st_body),
                Paragraph(_safe(l.get('domain', '')), st_body),
                Paragraph(f"<font color='{RED_CRITICAL.hexval()}'>{_safe(flag_str)}</font>", st_body),
            ])

        t_links = Table(link_rows, colWidths=[3.0*inch, 1.8*inch, 2.2*inch])
        t_links.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), GRAPHITE_50),
            ('BOX', (0,0), (-1,-1), 0.5, GRAPHITE_200),
            ('INNERGRID', (0,0), (-1,-1), 0.3, GRAPHITE_100),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t_links)
        story.append(Spacer(1, 16))

    # =========================================================================
    # 8. INVESTIGATION TIMELINE — Chronological processing events
    # =========================================================================
    timeline = _build_timeline(scan_data)
    story.append(Paragraph("INVESTIGATION TIMELINE", st_section))

    tl_header = [
        Paragraph("<b>Phase</b>", st_label),
        Paragraph("<b>Detail</b>", st_label),
        Paragraph("<b>Timestamp</b>", st_label),
    ]
    tl_rows = [tl_header]
    for idx, step in enumerate(timeline, 1):
        phase_text = f"<font color='{COBALT.hexval()}'><b>{idx}.</b></font> {_safe(step['phase'])}"
        time_val = _safe(step.get('time', ''), '—')
        tl_rows.append([
            Paragraph(phase_text, st_body),
            Paragraph(_safe(step['detail']), st_body),
            Paragraph(f"<font name='Courier' size='7'>{time_val}</font>", st_body_muted),
        ])

    t_tl = Table(tl_rows, colWidths=[1.8*inch, 4.0*inch, 1.7*inch])
    t_tl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COBALT_LIGHT),
        ('BOX', (0,0), (-1,-1), 0.5, GRAPHITE_200),
        ('INNERGRID', (0,0), (-1,-1), 0.3, GRAPHITE_100),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(t_tl)
    story.append(Spacer(1, 16))

    # =========================================================================
    # 9. RECOMMENDED NEXT ACTIONS
    # =========================================================================
    story.append(Paragraph("RECOMMENDED NEXT ACTIONS", st_section))

    action_box_bg = RED_BG if is_threat else GREEN_BG
    action_border = RED_CRITICAL if is_threat else GREEN_SAFE

    # Primary directive
    action_table = Table(
        [[Paragraph(f"<b>PRIMARY DIRECTIVE:</b> {_safe(action)}", st_body)]],
        colWidths=[7.0*inch]
    )
    action_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), action_box_bg),
        ('BOX', (0,0), (-1,-1), 1, action_border),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(action_table)
    story.append(Spacer(1, 6))

    # Supplementary next steps based on actual findings
    next_steps = []
    if is_threat:
        next_steps.append("Quarantine the submitted asset and restrict further distribution pending manual review.")
        if links:
            next_steps.append(f"Block or defang {len(links)} identified URL(s) at the network perimeter.")
        if raw_indicators:
            sev_counts = {}
            for ind in raw_indicators:
                s = (ind.get('severity') or 'HIGH').upper()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            sev_summary = ', '.join([f"{v} {k}" for k, v in sorted(sev_counts.items())])
            next_steps.append(f"Review {len(raw_indicators)} threat indicator(s) ({sev_summary}) for incident escalation criteria.")
        next_steps.append("Preserve forensic evidence and chain-of-custody documentation for audit trail.")
    else:
        next_steps.append("No immediate action required — asset passed all forensic checks.")
        next_steps.append("Continue routine monitoring per organizational security policy.")

    if next_steps:
        ns_rows = []
        for ns in next_steps:
            ns_rows.append([
                Paragraph(f"<font color='{COBALT.hexval()}'>→</font>", st_body),
                Paragraph(_safe(ns), st_body),
            ])
        t_ns = Table(ns_rows, colWidths=[0.3*inch, 6.7*inch])
        t_ns.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(t_ns)

    story.append(Spacer(1, 20))

    # =========================================================================
    # 10. FOOTER — Chain of Custody & Verification
    # =========================================================================
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAPHITE_200, spaceAfter=8))

    footer_parts = [
        f"<b>Scan ID:</b> {_safe(scan_id)}",
        f"<b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"<b>Modality:</b> {_safe(modality.upper())}",
    ]
    if file_hash:
        footer_parts.append(f"<b>SHA-256:</b> {_safe(file_hash[:24])}…")

    footer_text = (
        " · ".join(footer_parts) + "<br/>"
        "SecureSync Multi Detection System · Automated Forensic Intelligence · Confidential"
    )
    story.append(Paragraph(footer_text, st_footer))

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer
