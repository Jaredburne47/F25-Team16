# sponsor_message_email.py
import smtplib
import ssl
from email.message import EmailMessage
from html import escape

# Reuse your existing config. You can also `from applicationEmail import ...`
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # consider moving to env var in prod

def send_sponsor_message_email(to_email: str,
                               driver_username: str,
                               sponsor_username: str,
                               subject: str,
                               message: str) -> None:
    """Send a sponsor->driver message email with text + HTML parts."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"Team16 Sponsor <{SENDER_EMAIL}>"
    msg["To"] = to_email

    # Plain text (fallback)
    text = (
        f"Hello {driver_username},\n\n"
        f"{message}\n\n"
        f"-- Sent by sponsor: {sponsor_username}"
    )
    msg.set_content(text)

    # HTML version
    safe_msg = escape(message).replace("\n", "<br>")
    html = f"""
    <html>
      <body>
        <p>Hello {escape(driver_username)},</p>
        <p>{safe_msg}</p>
        <hr>
        <p><em>Sent by sponsor: {escape(sponsor_username)}</em></p>
      </body>
    </html>
    """
    msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
