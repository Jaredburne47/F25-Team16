# driverAddPointsEmail.py

import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_points_added_email(recipient, username, points):
    msg = EmailMessage()
    msg["Subject"] = "Welcome to the Good Driver Incentive Program"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Dear {username},

{points} points were added to your account. Congrats!

Thanks,
Team 16
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Points added email sent to {recipient}")

# allow command-line usage too
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python welcomeEmail.py recipient@example.com username password")
        sys.exit(1)
    send_points_added_email(sys.argv[1], sys.argv[2], sys.argv[3])
