from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User
from services.email_service import send_email
from services.otp_service import generate_otp, otp_cache
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
import os, random, string

router = APIRouter(prefix="/api/auth", tags=["Auth"])

SECRET_KEY = os.getenv("SECRET_KEY", "secret-key")
ALGORITHM = "HS256"

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

# --- Helpers ---
def create_token(user_id, role):
    data = {"sub": user_id, "role": role}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(lambda token: token)):
    return decode_token(token)

def decode_token(token):
    try:
        data = jwt.decode(token.replace("Bearer ", ""), SECRET_KEY, algorithms=[ALGORITHM])
        return type("UserObj", (), data)
    except:
        raise HTTPException(status_code=401, detail="Invalid token")


# OTP Request
@router.post("/request-otp")
def request_otp(payload: dict, db: Session = Depends(db)):
    email = payload["email"].lower()
    otp = generate_otp()
    otp_cache[email] = otp

    send_email(email, "Trauma Team OTP", f"Your OTP is <b>{otp}</b> (valid 10 min)")
    return {"message": f"OTP sent to {email}"}


# Verify OTP
@router.post("/verify-otp")
def verify_otp(payload: dict, db: Session = Depends(db)):
    email = payload["email"].lower()
    otp = payload["otp"]

    if otp_cache.get(email) != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    password = "".join(random.choices(string.ascii_letters + string.digits, k=10))

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user_id = f"TTI-{random.randint(100000,999999)}"
        hashed = pwd.hash(password)
        user = User(user_id=user_id, email=email, password_hash=hashed)
        db.add(user)
        db.commit()

    token = create_token(user.user_id, "user")
    return {
        "access_token": token,
        "user": {"user_id": user.user_id, "email": user.email},
        "password": password
    }


# Credential Login
@router.post("/login")
def login(payload: dict, db: Session = Depends(db)):
    user = db.query(User).filter(User.user_id == payload["user_id"]).first()
    if not user or not pwd.verify(payload["password"], user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_token(user.user_id, "user")
    return {"access_token": token, "user": {"user_id": user.user_id, "email": user.email}}


# Admin Login
@router.post("/admin")
def admin_login(payload: dict):
    if payload["username"] != os.getenv("ADMIN_USERNAME") or payload["password"] != os.getenv("ADMIN_PASSWORD"):
        raise HTTPException(status_code=400, detail="Invalid admin credentials")

    token = create_token("ADMIN", "admin")
    return {"access_token": token, "user": {"user_id": "ADMIN", "email": "admin"}}

