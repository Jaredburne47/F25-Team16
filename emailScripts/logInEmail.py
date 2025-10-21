# welcomeEmail.py

import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_login_email(recipient, username):
    msg = EmailMessage()
    msg["Subject"] = "Log In"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Dear {username},

You have just logged in to your account. If this was not you, please respond to this email notifying us right away. 
We’re excited to have you on board.

Thanks,
Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Log in email sent to {recipient}")

# allow command-line usage too
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python logInEmail.py recipient@example.com username")
        sys.exit(1)
    send_login_email(sys.argv[1], sys.argv[2])
