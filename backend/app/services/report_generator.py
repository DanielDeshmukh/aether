import asyncio
import logging
import os
import tempfile
from pathlib import Path

from fastapi import HTTPException

logger = logging.getLogger("aether.report_generator")


def generate_pdf_sync(temp_path: str) -> bytes:
    """
    Synchronous helper to generate PDF using Playwright.
    Run in a thread to avoid NotImplementedError on Windows with Python 3.13.
    """
    from playwright.sync_api import sync_playwright
    
    try:
        with sync_playwright() as p:
            # launch browser with --no-sandbox for stability
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                # Use Path.as_uri() to handle Windows absolute paths correctly
                page.goto(Path(temp_path).as_uri())
                # Ensure fonts and network resources are fully loaded
                page.wait_for_load_state("networkidle")
                
                pdf_bytes = page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"}
                )
                return pdf_bytes
            finally:
                browser.close()
    except Exception as e:
        logger.error(f"Playwright sync generation failed: {str(e)}")
        raise


async def render_pdf_report(scan: dict, vulnerabilities: list[dict], profiles: list[dict]) -> bytes:
    # Compute logo path relative to this file
    current_dir = Path(__file__).resolve().parent
    logo_path = (current_dir / ".." / ".." / ".." / "frontend" / "public" / "images" / "logo.png").resolve()
    logo_uri = logo_path.as_uri() if logo_path.exists() else None

    target_url = scan.get("target_url", "unknown")
    
    # Map vulnerabilities to HTML
    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "INFO": "#6b7280",
    }
    if not vulnerabilities:
        vulnerabilities_content = '<p class="item-text">No vulnerabilities detected.</p>'
    else:
        cards = []
        for v in vulnerabilities:
            title = v.get("title", "Untitled Finding")
            severity = (v.get("severity") or "unknown").upper()
            detail = v.get("detail", "No detail provided.")
            category = v.get("category", "")
            evidence = v.get("evidence_snippet", "")
            solution = v.get("provided_solution", "")
            color = severity_colors.get(severity, "#6b7280")
            card = f"""
            <div style="border:1px solid #1A1A1A; border-left:4px solid {color}; padding:20px; margin-bottom:16px; background:#0d0d0d;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <span style="font-weight:700; font-size:14px; color:#fff;">{title}</span>
                    <span style="background:{color}; color:#000; padding:3px 10px; font-size:11px; font-weight:700; text-transform:uppercase;">{severity}</span>
                </div>
                <div style="color:#888; font-size:11px; margin-bottom:8px; font-family:'JetBrains Mono',monospace;">{category}</div>
                <p style="color:#ccc; font-size:13px; line-height:1.6; margin-bottom:10px;">{detail}</p>
                {"<div style='background:#111; padding:10px; margin-top:8px; border:1px solid #222; font-family:monospace; font-size:11px; color:#aaa; white-space:pre-wrap;'>" + evidence + "</div>" if evidence else ""}
                {"<div style='margin-top:8px; color:#22c55e; font-size:12px;'><strong>Fix:</strong> " + solution + "</div>" if solution else ""}
            </div>
            """
            cards.append(card)
        vulnerabilities_content = "".join(cards)

    # Map profiles to HTML
    if profiles:
        profile_lines = []
        for p in profiles:
            label = p.get("label", "Unknown")
            summary = p.get("summary", "")
            profile_lines.append(f"<strong>{label}</strong>: {summary}")
        profiles_content = "<br/>".join(profile_lines)
    else:
        profiles_content = "No profile data available."

    # Map diagnosis to HTML
    final_report = scan.get("final_report") or {}
    diagnosis_content = final_report.get("synthesis") or final_report.get("report") or "No diagnosis available."

    # Executive summary
    threat_level = (final_report.get("threat_level") or scan.get("threat_level") or "unknown").upper()
    threat_color = severity_colors.get(threat_level, "#6b7280")
    vuln_count = len(vulnerabilities)
    severity_counts = {}
    for v in vulnerabilities:
        sev = (v.get("severity") or "unknown").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    summary_bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            c = severity_colors.get(sev, "#6b7280")
            summary_bars += f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;"><span style="background:{c};color:#000;padding:2px 8px;font-size:10px;font-weight:700;min-width:60px;text-align:center;">{sev}</span><span style="color:#ccc;font-size:12px;">{count} finding{"s" if count != 1 else ""}</span></div>'

    # Strategy trace
    initial_plan = scan.get("initial_plan") or {}
    plan_steps = initial_plan.get("steps", []) if isinstance(initial_plan, dict) else (initial_plan if isinstance(initial_plan, list) else [])
    trace_html = ""
    for i, step in enumerate(plan_steps[:10]):
        label = step.get("label", f"Step {i+1}") if isinstance(step, dict) else f"Step {i+1}"
        message = step.get("message", "") if isinstance(step, dict) else str(step)
        trace_html += f'<div style="border-left:2px solid #d4af37;padding:8px 12px;margin-bottom:8px;background:#111;"><span style="color:#d4af37;font-size:11px;font-weight:700;">{label}</span><p style="color:#aaa;font-size:11px;margin-top:4px;">{message[:200]}</p></div>'
    if not trace_html:
        trace_html = '<p style="color:#666;font-size:12px;">No strategy trace available.</p>'

    # Scan metadata
    created_at = scan.get("created_at")
    completed_at = scan.get("completed_at")
    scan_status = (scan.get("status") or "unknown").upper()
    meta_items = [
        f"<strong>Scan ID:</strong> {str(scan.get('id', ''))[:8]}",
        f"<strong>Status:</strong> {scan_status}",
        f"<strong>Threat Level:</strong> <span style='color:{threat_color}'>{threat_level}</span>",
        f"<strong>Total Findings:</strong> {vuln_count}",
    ]
    if created_at:
        meta_items.append(f"<strong>Started:</strong> {created_at.strftime('%Y-%m-%d %H:%M UTC') if hasattr(created_at, 'strftime') else str(created_at)}")
    if completed_at:
        meta_items.append(f"<strong>Completed:</strong> {completed_at.strftime('%Y-%m-%d %H:%M UTC') if hasattr(completed_at, 'strftime') else str(completed_at)}")
    meta_content = "<br/>".join(meta_items)

    html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&family=JetBrains+Mono&display=swap');
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        html, body {{
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            background-color: #0a0a0a !important;
            color: #ffffff !important;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            padding: 60px 50px;
        }}

        .header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 50px;
            border-bottom: 1px solid #1A1A1A;
            padding-bottom: 30px;
        }}

        .logo-wrap {{ display: flex; align-items: center; gap: 15px; }}
        .logo-img {{ height: 32px; width: auto; }}
        .brand {{ 
            font-weight: 900; 
            letter-spacing: 0.4em; 
            font-size: 22px; 
            color: #ffffff; 
            text-transform: uppercase;
        }}

        .report-type {{ 
            color: #d4af37 !important; 
            font-weight: 900; 
            font-size: 14px; 
            text-transform: uppercase;
            letter-spacing: 0.2em;
            border: 1px solid #d4af37;
            padding: 8px 16px;
        }}

        .banner {{ 
            background: #111111 !important; 
            border: 1px solid #1A1A1A; 
            padding: 30px; 
            margin-bottom: 40px; 
            border-left: 5px solid #d4af37 !important;
        }}

        .target-label {{ 
            color: #d4af37 !important; 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 11px; 
            text-transform: uppercase; 
            letter-spacing: 0.15em;
            display: block;
            margin-bottom: 10px;
        }}

        .target-url {{ 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 18px; 
            font-weight: 700;
            color: #ffffff;
        }}

        .section {{ 
            margin-bottom: 40px; 
        }}

        .section-title {{ 
            color: #d4af37 !important; 
            font-weight: 900; 
            font-size: 16px; 
            margin-bottom: 25px; 
            display: flex;
            align-items: center;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }}

        .section-title::before {{ 
            content: ""; 
            display: inline-block;
            width: 30px;
            height: 1px;
            background: #d4af37;
            margin-right: 15px;
        }}

        .content-card {{ 
            background: #0d0d0d !important;
            border: 1px solid #1A1A1A;
            padding: 30px;
            position: relative;
        }}

        .item-text {{ 
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px; 
            line-height: 1.8; 
            white-space: pre-wrap; 
            color: #e5e5e5;
        }}

        .footer {{
            position: fixed;
            bottom: 40px;
            left: 50px;
            right: 50px;
            border-top: 1px solid #1A1A1A;
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            color: #555555;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-wrap">
            {"<img src='" + logo_uri + "' class='logo-img' />" if logo_uri else ""}
            <span class="brand">AETHER</span>
        </div>
        <div class="report-type">Mission Debrief</div>
    </div>

    <div class="banner">
        <span class="target-label">Primary Intelligence Target</span>
        <span class="target-url">{target_url}</span>
    </div>

    <div class="section">
        <span class="section-title">Executive Summary</span>
        <div class="content-card">
            <div style="display:flex;align-items:center;gap:15px;margin-bottom:20px;">
                <span style="background:{threat_color};color:#000;padding:6px 16px;font-size:13px;font-weight:900;text-transform:uppercase;">Threat Level: {threat_level}</span>
                <span style="color:#888;font-size:12px;">{vuln_count} total finding{"s" if vuln_count != 1 else ""}</span>
            </div>
            {summary_bars}
        </div>
    </div>

    <div class="section">
        <span class="section-title">Scan Metadata</span>
        <div class="content-card">
            <p class="item-text">{meta_content}</p>
        </div>
    </div>

    <div class="section">
        <span class="section-title">Surface Vulnerabilities</span>
        {vulnerabilities_content}
    </div>

    <div class="section">
        <span class="section-title">Target Profile</span>
        <div class="content-card">
            <p class="item-text">{profiles_content}</p>
        </div>
    </div>

    <div class="section">
        <span class="section-title">Agentic Diagnosis</span>
        <div class="content-card">
            <p class="item-text">{diagnosis_content}</p>
        </div>
    </div>

    <div class="section">
        <span class="section-title">Strategy Trace</span>
        {trace_html}
    </div>

    <div class="footer">
        <span>AETHER OS v1.0 // Automated Heuristic Evaluation</span>
        <span>Secure Transmission // Confidential</span>
    </div>
</body>
</html>"""

    # Ensure cleanup requirement: write to temp file then delete
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tf:
        tf.write(html_template)
        temp_path = tf.name

    try:
        # Offload sync Playwright execution to a worker thread
        pdf_bytes = await asyncio.to_thread(generate_pdf_sync, temp_path)
        return pdf_bytes
    except Exception as e:
        logger.exception("PDF generation failed: %s", str(e))
        raise HTTPException(
            status_code=500, 
            detail="PDF generation failed. Check Playwright browser installation."
        )
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
