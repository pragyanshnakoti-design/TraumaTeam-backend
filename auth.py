from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import User
from schemas import UserCreate, OTPVerify
from services.otp_service import generate_otp, verify_otp_and_delete
from services.email_service import send_otp_email
from services.jwt_service import create_access_token, verify_token

router = APIRouter(prefix="/auth", tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# REGISTER — send OTP to email
@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    otp = generate_otp(db, user.email)
    send_otp_email(user.email, otp)
    return {"message": "OTP sent to email"}


# VERIFY OTP — create user after OTP success
@router.post("/verify-otp")
def verify_otp(otp_data: OTPVerify, db: Session = Depends(get_db)):
    if not verify_otp_and_delete(db, otp_data.email, otp_data.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    new_user = User(email=otp_data.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token({"email": otp_data.email})
    return {"message": "User verified", "access_token": token}


# LOGIN (email only)
class LoginRequest(BaseModel):
    email: str

@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == data.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")
    
    token = create_access_token({"email": data.email})
    return {"access_token": token}


# PROTECTED route helper
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload["email"]
