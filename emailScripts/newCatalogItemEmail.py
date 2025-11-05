# emailScripts/newCatalogItemEmail.py
import smtplib
import ssl
from email.message import EmailMessage

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_new_item_email(recipient: str, driver_username: str, sponsor_name: str,
                        item_name: str, points_cost: int | None = None):
    """
    Notify a driver that a sponsor they’re accepted with added a new item.
    """
    subj = f"New item added by {sponsor_name}"
    pts  = f" (Cost: {points_cost} pts)" if points_cost is not None else ""
    body = f"""\
Dear {driver_username},

{sponsor_name} just added a new item to their catalog:
- {item_name}{pts}

Open the app to take a look!

Thanks,
Team 16
"""

    msg = EmailMessage()
    msg["Subject"] = subj
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[newCatalogItemEmail] sent to {recipient} for item '{item_name}'")
