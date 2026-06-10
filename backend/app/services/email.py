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
