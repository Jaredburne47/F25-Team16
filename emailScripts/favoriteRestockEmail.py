# favoriteRestockEmail.py
import smtplib
import ssl
from email.message import EmailMessage

# Gmail SMTP config
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # same app password as others


def send_favorite_restock_email(recipient, username, item_name, sponsor_name, quantity):
    """
    Send an email to alert a driver that one of their favorite items is back in stock.
    """
    msg = EmailMessage()
    msg["Subject"] = f"'{item_name}' is Back in Stock!"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient

    msg.set_content(f"""\
Hi {username},

Good news! One of your favorite catalog items — "{item_name}" from {sponsor_name} — 
is now back in stock ({quantity} available).

Head over to your catalog to grab it before it’s gone!

{item_name}: https://yourappdomain.com/item_catalog

Best,
Team 16 Incentives
""")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"Favorite restock email sent to {recipient} for item '{item_name}'.")


# Allow command-line usage for testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 6:
        print("Usage: python favoriteRestockEmail.py recipient@example.com username item_name sponsor_name quantity")
        sys.exit(1)
    send_favorite_restock_email(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
