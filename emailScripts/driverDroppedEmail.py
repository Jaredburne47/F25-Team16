import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_driver_dropped_email(recipient_email: str, sponsor_username: str, driver_username: str):
    msg = EmailMessage()
    msg["Subject"] = "Your sponsorship has ended"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email

    msg.set_content(f"""\
Dear {driver_username},

Your sponsor "{sponsor_username}" has ended your sponsorship.
Thank you for your loyalty and dedication during your time together. 
Your contributions and commitment have been greatly appreciated, and we wish you continued success on your journey.

Thanks,
Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Driver dropped email sent to {recipient_email}")
