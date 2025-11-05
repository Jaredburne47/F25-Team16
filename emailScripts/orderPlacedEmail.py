# emailScripts/orderPlacedEmail.py
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, Dict, Any

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "team16gdip@gmail.com"
SENDER_PASSWORD = "jsxl pnun vdts mxhs"  # app password

def send_order_placed_email(
    recipient: str,
    username: str,
    items: Iterable[Dict[str, Any]],
    total_points: int,
    delivery_address: str | None,
    expected_date_str: str | None,
    sponsor: str | None
) -> None:
    """
    Send a confirmation email when an order is placed.

    items: iterable of dicts with keys:
        - name (str)
        - quantity (int)
        - points_cost (int)  # per-unit cost in points
    """
    lines = []
    for it in items:
        nm = str(it.get("name") or "Item")
        qty = int(it.get("quantity") or 0)
        pts = int(it.get("points_cost") or 0)
        lines.append(f"  • {nm} — {qty} × {pts} pts")

    items_block = "\n".join(lines) if lines else "  (No line items could be listed.)"
    addr_block = delivery_address or "(No address on file)"
    eta_block  = expected_date_str or "(TBD)"
    sponsor_line = f"\nSponsor: {sponsor}" if sponsor else ""

    body = f"""\
Dear {username},

Your order has been placed successfully!{sponsor_line}

Items:
{items_block}

Total points charged: {total_points} pts
Delivery address: {addr_block}
Expected delivery date: {eta_block}

You can view your order status anytime in the app under Orders.

Thanks,
Team 16
"""

    msg = EmailMessage()
    msg["Subject"] = "Order Placed Confirmation"
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print(f"[orderPlacedEmail] sent to {recipient} (user {username})")
