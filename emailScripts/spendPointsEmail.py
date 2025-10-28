import smtplib
import ssl
from email.message import EmailMessage

# Reuse your existing config values
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_spent_points_email(recipient: str, username: str, total_points: int):
    msg = EmailMessage()
    msg["Subject"] = "Points Redeemed in Catalog"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hi {username},

You successfully spent {total_points} points on catalog items.
Your order is being processed, and your remaining balance has been updated in your dashboard.

Thank you for participating!
— Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[Email] Spent points notification sent to {recipient} (spent={total_points})")
