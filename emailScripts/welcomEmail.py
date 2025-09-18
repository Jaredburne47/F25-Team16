import smtplib
import ssl
from email.message import EmailMessage
import sys

if len(sys.argv) < 2:
    print("Usage: python welcomeEmail.py recipient@example.com")
    sys.exit(1)

recipient = sys.argv[1]

# --- Email account you send from ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465             
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"

# --- Build the email ---
msg = EmailMessage()
msg["Subject"] = "Welcome to the Good Driver Incentive Program"
msg["From"] = SENDER_EMAIL
msg["To"] = recipient
msg.set_content("""\
Hello,

Welcome to the Good Driver Incentive Program! 
We’re excited to have you on board.

Team 16
""")

# --- Send ---
context = ssl.create_default_context()
with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.send_message(msg)

print(f"Welcome email sent to {recipient}")
