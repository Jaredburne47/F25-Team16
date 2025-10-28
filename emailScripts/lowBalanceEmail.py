import smtplib
import ssl
from email.message import EmailMessage

# Reuse your existing config values
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_low_balance_email(recipient: str, username: str, points: int, threshold: int = 50):
    msg = EmailMessage()
    msg["Subject"] = "Low Points Balance Alert"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hi {username},

Heads up—your current points balance is {points}, which is below the minimum threshold of {threshold} points.

Consider earning more points so you can keep redeeming rewards.

— Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[Email] Low balance alert sent to {recipient} (balance={points})")
