import os
import logging

logger = logging.getLogger("aether.email")

_MAGIC_LINK_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ margin: 0; padding: 0; background: #000; font-family: 'Courier New', monospace; }}
  .container {{ max-width: 520px; margin: 40px auto; background: #0c0c0d; border: 1px solid #333; border-radius: 12px; padding: 40px; }}
  .logo {{ text-align: center; margin-bottom: 30px; }}
  .logo span {{ color: #FFC107; font-size: 28px; font-weight: 900; letter-spacing: 6px; }}
  .title {{ color: #fff; font-size: 14px; text-transform: uppercase; letter-spacing: 4px; text-align: center; margin-bottom: 8px; }}
  .subtitle {{ color: #7D7D7D; font-size: 10px; text-transform: uppercase; letter-spacing: 3px; text-align: center; margin-bottom: 30px; }}
  .btn {{ display: block; width: 100%; padding: 16px; background: #FFC107; color: #000; text-align: center; text-decoration: none; font-weight: 900; font-size: 11px; text-transform: uppercase; letter-spacing: 4px; border-radius: 8px; margin: 24px 0; }}
  .footer {{ color: #555; font-size: 9px; text-transform: uppercase; letter-spacing: 2px; text-align: center; margin-top: 30px; line-height: 1.8; }}
  .divider {{ border: none; border-top: 1px solid #333; margin: 24px 0; }}
</style>
</head>
<body>
  <div class="container">
    <div class="logo"><span>AETHER</span></div>
    <p class="title">Access Request</p>
    <p class="subtitle">Neural orchestration engine</p>
    <hr class="divider">
    <p style="color: #aaa; font-size: 12px; line-height: 1.8; text-align: center;">
      Click the button below to securely access AETHER.
    </p>
    <a href="{magic_link_url}" class="btn">Authorize Access</a>
    <p style="color: #666; font-size: 9px; text-align: center; word-break: break-all;">
      Or paste this link into your browser:<br>{magic_link_url}
    </p>
    <hr class="divider">
    <p class="footer">
      This link expires in {expiry_minutes} minutes.<br>
      If you did not request this, ignore this message.
    </p>
  </div>
</body>
</html>
""".strip()


async def send_magic_link_email(to_email: str, magic_link_url: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587").strip() or "587")
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "AETHER <noreply@aether.local>").strip()

    if not smtp_host:
        logger.warning(
            "SMTP not configured — magic link for %s would be sent to:\n%s",
            to_email,
            magic_link_url,
        )
        return True

    html_body = _MAGIC_LINK_HTML_TEMPLATE.format(
        magic_link_url=magic_link_url,
        expiry_minutes=15,
    )

    try:
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = "AETHER — Access Link"
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            username=smtp_user or None,
            password=smtp_password or None,
            use_tls=False,
            start_tls=True,
        )
        logger.info("Magic link email sent to %s", to_email)
        return True
    except Exception as exc:
        logger.exception("Failed to send magic link email to %s: %s", to_email, exc)
        return False


_REPORT_EMAIL_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ margin: 0; padding: 0; background: #000; font-family: 'Courier New', monospace; }}
  .container {{ max-width: 520px; margin: 40px auto; background: #0c0c0d; border: 1px solid #333; border-radius: 12px; padding: 40px; }}
  .logo {{ text-align: center; margin-bottom: 30px; }}
  .logo span {{ color: #FFC107; font-size: 28px; font-weight: 900; letter-spacing: 6px; }}
  .title {{ color: #fff; font-size: 14px; text-transform: uppercase; letter-spacing: 4px; text-align: center; margin-bottom: 8px; }}
  .subtitle {{ color: #7D7D7D; font-size: 10px; text-transform: uppercase; letter-spacing: 3px; text-align: center; margin-bottom: 30px; }}
  .divider {{ border: none; border-top: 1px solid #333; margin: 24px 0; }}
  .info {{ color: #aaa; font-size: 12px; line-height: 1.8; text-align: center; }}
  .target {{ color: #FFC107; font-size: 12px; font-weight: bold; text-align: center; margin: 16px 0; }}
  .stats {{ display: flex; justify-content: space-around; margin: 24px 0; }}
  .stat {{ text-align: center; }}
  .stat-value {{ color: #fff; font-size: 18px; font-weight: bold; }}
  .stat-label {{ color: #7D7D7D; font-size: 9px; text-transform: uppercase; letter-spacing: 1px; }}
  .footer {{ color: #555; font-size: 9px; text-transform: uppercase; letter-spacing: 2px; text-align: center; margin-top: 30px; line-height: 1.8; }}
</style>
</head>
<body>
  <div class="container">
    <div class="logo"><span>AETHER</span></div>
    <p class="title">Security Report</p>
    <p class="subtitle">Scan completed</p>
    <hr class="divider">
    <p class="info">Your security scan has been completed. Please find the detailed report attached.</p>
    <div class="target">{target_url}</div>
    <div class="stats">
      <div class="stat">
        <div class="stat-value">{vuln_count}</div>
        <div class="stat-label">Vulnerabilities</div>
      </div>
      <div class="stat">
        <div class="stat-value">{threat_level}</div>
        <div class="stat-label">Threat Level</div>
      </div>
    </div>
    <hr class="divider">
    <p class="footer">
      Report attached as PDF.<br>
      Generated by AETHER Security Engine.
    </p>
  </div>
</body>
</html>
""".strip()


async def send_report_email(
    to_email: str,
    target_url: str,
    vuln_count: int,
    threat_level: str,
    pdf_bytes: bytes,
    scan_id: str,
) -> bool:
    """
    Send a security report email with PDF attachment.
    
    Args:
        to_email: Recipient email address
        target_url: The scanned target URL
        vuln_count: Number of vulnerabilities found
        threat_level: Overall threat level
        pdf_bytes: PDF report content as bytes
        scan_id: Scan identifier
        
    Returns:
        True if email sent successfully, False otherwise
    """
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587").strip() or "587")
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "AETHER <noreply@aether.local>").strip()

    if not smtp_host:
        logger.warning(
            "SMTP not configured — report email for scan %s to %s would be sent (PDF attached)",
            scan_id,
            to_email,
        )
        return True

    html_body = _REPORT_EMAIL_HTML_TEMPLATE.format(
        target_url=target_url,
        vuln_count=vuln_count,
        threat_level=threat_level.upper(),
    )

    try:
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.application import MIMEApplication

        msg = MIMEMultipart("mixed")
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = f"AETHER Security Report — {target_url}"
        
        # Add HTML body
        html_part = MIMEText(html_body, "html", "utf-8")
        msg.attach(html_part)
        
        # Add PDF attachment
        pdf_attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
        pdf_attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=f"aether-report-{scan_id[:8]}.pdf",
        )
        msg.attach(pdf_attachment)

        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            username=smtp_user or None,
            password=smtp_password or None,
            use_tls=False,
            start_tls=True,
        )
        logger.info("Report email sent to %s for scan %s", to_email, scan_id)
        return True
    except Exception as exc:
        logger.exception("Failed to send report email to %s for scan %s: %s", to_email, scan_id, exc)
        return False
