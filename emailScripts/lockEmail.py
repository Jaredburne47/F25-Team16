import smtplib, ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_lock_email(to_email, username, role, locked_until_str):
    msg = EmailMessage()
    msg["Subject"] = f"{role.capitalize()} Account Locked"
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg.set_content(f"""Hello {username},

Your {role} account has been locked due to multiple failed login attempts.
It will unlock at: {locked_until_str}

If this wasn’t you, please reset your password.

- Team 16
""")
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=ctx) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
