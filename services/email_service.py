import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

def send_otp_email(email: str, otp: str):
    """
    Send OTP email using SendGrid API
    """
    if not SENDGRID_API_KEY:
        print(f"[DEBUG] OTP for {email}: {otp} (SENDGRID key not configured)")
        return

    message = Mail(
        from_email="no-reply@traumateam.ai",
        to_emails=email,
        subject="Your Trauma Team OTP Code",
        html_content=f"<h2>Your OTP is: {otp}</h2><p>This code expires in 5 minutes.</p>",
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
        print(f"OTP email sent to {email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email → {e}")
