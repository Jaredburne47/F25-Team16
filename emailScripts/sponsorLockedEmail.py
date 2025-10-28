import smtplib
import ssl
from email.message import EmailMessage

# --- Email Config ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # Gmail app password

def send_sponsor_locked_email(admin_email: str, sponsor_username: str, locked_until: str):
    msg = EmailMessage()
    msg["Subject"] = f"Sponsor Account Locked: {sponsor_username}"
    msg["From"] = SENDER_EMAIL
    msg["To"] = admin_email

    msg.set_content(f"""\
Hello Admin,

Sponsor account "{sponsor_username}" has been locked due to too many failed login attempts.

The lockout period lasts until: {locked_until}

Please review the account and take appropriate action.

– Team 16 System Notification
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[Email] Sponsor lockout alert sent to admin ({admin_email}) for {sponsor_username}")
