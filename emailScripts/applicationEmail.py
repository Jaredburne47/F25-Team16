# applicationEmail.py

import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_application_email(recipient, sponsor_username):
    msg = EmailMessage()
    msg["Subject"] = "Driver Application"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Dear {sponsor_username},

You have a new driver application. Please review at your convenience.

Thanks,
Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Application email sent to {recipient}")

# allow command-line usage too
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python applicationEmail.py recipient@example.com username")
        sys.exit(1)
    send_application_email(sys.argv[1], sys.argv[2])
