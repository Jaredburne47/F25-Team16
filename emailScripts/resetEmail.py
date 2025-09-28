# resetEmail.py

import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_reset_email(recipient, username, reset_link):
    msg = EmailMessage()
    msg["Subject"] = "Password Reset Request"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hello {username},

We received a request to reset your password for the Good Driver Incentive Program.

To reset your password, click the link below (valid for a limited time):
{reset_link}

If you did not request this, please ignore this email.

Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Password reset email sent to {recipient}")


# allow command-line usage for testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python resetEmail.py recipient@example.com username reset_link")
        sys.exit(1)
    send_reset_email(sys.argv[1], sys.argv[2], sys.argv[3])
