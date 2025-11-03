import smtplib
import ssl
from email.message import EmailMessage

# Reuse your existing config values
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_cancelled_purchase_email(recipient: str, username: str):
    msg = EmailMessage()
    msg["Subject"] = "Points Redeemed in Catalog"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hi {username},

You successfully cancelled your order. Your points have been added back to your balance.

Thanks,
— Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[Email] Order cancelled notification sent to {recipient}")
