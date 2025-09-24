import smtplib
import ssl
from email.message import EmailMessage
import sys

if len(sys.argv) < 4:
    print("Usage: python welcomeEmail.py recipient@example.com username password")
    sys.exit(1)

recipient = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

# --- Email account you send from ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # your app password

# --- Build the email ---
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

# --- Send ---
context = ssl.create_default_context()
with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.send_message(msg)

print(f"Welcome email sent to {recipient}")
