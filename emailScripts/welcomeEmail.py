# welcomeEmail.py

import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_welcome_email(recipient, username, password):
    msg = EmailMessage()
    msg["Subject"] = "Welcome to the Good Driver Incentive Program"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hello,

Welcome to the Good Driver Incentive Program! 
We’re excited to have you on board.

Here are your credentials:
Username: {username}
Password: {password}

Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Welcome email sent to {recipient}")

# allow command-line usage too
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python welcomeEmail.py recipient@example.com username password")
        sys.exit(1)
    send_welcome_email(sys.argv[1], sys.argv[2], sys.argv[3])
