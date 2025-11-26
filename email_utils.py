import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi import HTTPException

from config import SMTP_SERVER, SMTP_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM


def send_otp_email(to_email: str, otp: str, temp_password: str):
    """
    Sends OTP + temp password to user.
    Raises HTTPException if email config is missing or sending fails.
    """
    if not MAIL_USERNAME or not MAIL_PASSWORD or not MAIL_FROM:
        raise HTTPException(
            status_code=500,
            detail="Email service not configured (MAIL_USERNAME / MAIL_PASSWORD / MAIL_FROM).",
        )

    subject = "Trauma Team International - OTP & Temporary Credentials"

    text_body = f"""
Your Trauma Team OTP is: {otp}

Use this OTP to verify your email.

After verification, you can login with:
Temp Password: {temp_password}
(Your permanent User ID will be shown on screen.)

Do not share these credentials with anyone.

- Trauma Team International
"""

    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(text_body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())
    except Exception as e:
        print(f"❌ Failed to send OTP email: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to send OTP email. Contact support.",
        )
