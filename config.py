import os
from datetime import timedelta

# JWT / Auth
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-traumateam-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")  # 24 hours
)

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Email / SMTP (Gmail or similar)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")  # e.g. dispatch.traumateam@gmail.com
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")  # Gmail App Password
MAIL_FROM = os.getenv("MAIL_FROM", MAIL_USERNAME or "no-reply@traumateam.com")


def access_token_expires_delta() -> timedelta:
    return timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
