import random
from datetime import datetime, timedelta

otp_store = {}  # temporary in-memory storage

def generate_otp(email: str) -> str:
    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=5)
    otp_store[email] = {"otp": otp, "expiry": expiry}
    return otp

def verify_otp_and_delete(email: str, otp: str) -> bool:
    record = otp_store.get(email)
    if not record:
        return False

    if record["otp"] != otp:
        return False

    if datetime.utcnow() > record["expiry"]:
        del otp_store[email]
        return False

    # OTP valid -> delete from store
    del otp_store[email]
    return True
