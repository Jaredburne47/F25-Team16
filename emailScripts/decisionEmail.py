import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_decision_email(recipient, driver_name, sponsor_name, decision):
    msg = EmailMessage()
    msg["Subject"] = f"Your Application Has Been {decision.capitalize()}"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""
Hello {driver_name},

Your application to join sponsor **{sponsor_name}** has been {decision}.

If you have any questions, please reach out to your sponsor.

- Team 16
    """)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Decision email sent to {recipient} ({decision}).")
