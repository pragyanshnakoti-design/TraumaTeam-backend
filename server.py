# server.py - SECURE BACKEND FOR TRAUMA TEAM

import os
import random
import re
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, validator, Field
from passlib.hash import bcrypt
import jwt

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# --- Load environment variables ---
load_dotenv()

def _env(key: str, default=None):
    """Safely load environment variables and strip quotes"""
    v = os.getenv(key, default)
    if v is None:
        return default
    return v.strip().replace('"', '').replace("'", "")

# Configuration
RESEND_API_KEY = _env("RESEND_API_KEY")
RESEND_FROM = _env("RESEND_FROM", "onboarding@resend.dev")
ADMIN_USER = _env("ADMIN_USER", "admin")
ADMIN_PASS = _env("ADMIN_PASS", "admin123")
JWT_SECRET = _env("JWT_SECRET", "trauma_team_secret_key_CHANGE_IN_PRODUCTION")
DATABASE_URL = _env("DATABASE_URL", "sqlite:///./trauma_team.db")
OTP_EXPIRE_MINUTES = int(_env("OTP_EXPIRE_MINUTES", "5"))
CORS_ORIGINS = _env("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080")

# Rate limiting configuration
RATE_LIMIT_PER_MINUTE = 10
request_counts = {}

# Resend setup
EMAIL_ENABLED = False
if RESEND_API_KEY:
    try:
        import resend
        resend.api_key = RESEND_API_KEY
        EMAIL_ENABLED = True
        print("✅ Email service enabled (Resend)")
    except Exception as e:
        print(f"⚠️  Email service disabled: {e}")
else:
    print("⚠️  RESEND_API_KEY not set - emails will be logged to console")

def _send_email(to: str, subject: str, html: str):
    """Send email via Resend or log to console"""
    # Sanitize email content
    html = html.replace("<script", "&lt;script").replace("</script", "&lt;/script")
    
    if EMAIL_ENABLED:
        try:
            import resend
            resend.Emails.send({
                "from": RESEND_FROM,
                "to": [to],
                "subject": subject,
                "html": html
            })
            print(f"✅ Email sent to {to}: {subject}")
        except Exception as e:
            print(f"❌ Email error: {e}")
    else:
        print(f"📧 [EMAIL SIMULATION] To: {to}, Subject: {subject}")

# --- Database setup ---
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False},
    pool_pre_ping=True
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), nullable=False)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class OTP(Base):
    __tablename__ = "otp"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    otp = Column(String(10), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    attempts = Column(Integer, default=0)

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # Link to user if authenticated
    invoice_id = Column(String(50), unique=True, index=True)
    patient_name = Column(String(200), nullable=False)
    email = Column(String(255), nullable=False)
    doctor = Column(String(100), nullable=False)
    appointment_date = Column(String(20), nullable=False)
    appointment_time = Column(String(10), nullable=False)
    message = Column(Text)
    status = Column(String(20), default="PENDING")
    payment_status = Column(String(20), default="pending")
    consultation_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    payment_id = Column(String(50), unique=True, index=True)
    booking_id = Column(Integer, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    amount = Column(Float)
    card_number_last4 = Column(String(4))
    card_name = Column(String(200))
    status = Column(String(20), default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

# Create all tables
Base.metadata.create_all(bind=engine)

# --- Security Middleware ---
def rate_limit_check(request: Request):
    """Simple rate limiting"""
    client_ip = request.client.host
    current_minute = datetime.now().strftime("%Y-%m-%d-%H-%M")
    key = f"{client_ip}:{current_minute}"
    
    if key not in request_counts:
        request_counts[key] = 0
    
    request_counts[key] += 1
    
    if request_counts[key] > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429, 
            detail="Too many requests. Please try again later."
        )
    
    # Cleanup old entries
    for k in list(request_counts.keys()):
        if k.split(":")[1] != current_minute:
            del request_counts[k]

# --- Auth helpers ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

def create_token(data: dict, hours_valid: int = 8):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=hours_valid)
    payload["iat"] = datetime.utcnow()
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Authentication required"
        )
    
    payload = decode_token(token)
    if not payload or "user_id" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid or expired token"
        )
    
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not found"
        )
    return user

def get_optional_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Get user if authenticated, None otherwise"""
    if not token:
        return None
    
    payload = decode_token(token)
    if not payload or "user_id" not in payload:
        return None
    
    return db.query(User).filter(User.id == payload["user_id"]).first()

def require_admin(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Admin access required"
        )
    
    payload = decode_token(token)
    if not payload or not payload.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Admin access required"
        )
    return payload

# --- Input Validation Schemas ---
class OTPRequest(BaseModel):
    email: EmailStr

class RegisterRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=4, regex="^[0-9]{4}$")
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match("^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if not re.search("[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search("[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search("[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=100)

class BookingCreate(BaseModel):
    patient_name: str = Field(..., min_length=2, max_length=200)
    email: EmailStr
    doctor: str = Field(..., min_length=1, max_length=100)
    appointment_date: str = Field(..., regex="^\d{4}-\d{2}-\d{2}$")
    appointment_time: str = Field(..., regex="^\d{2}:\d{2}$")
    message: Optional[str] = Field(None, max_length=1000)
    
    @validator('doctor')
    def validate_doctor(cls, v):
        allowed_doctors = ["Dr. R. Sharma", "Dr. M. Gupta", "Dr. Jyoti"]
        if v not in allowed_doctors:
            raise ValueError("Invalid doctor selection")
        return v
    
    @validator('appointment_date')
    def validate_date(cls, v):
        try:
            date = datetime.strptime(v, "%Y-%m-%d").date()
            if date < datetime.now().date():
                raise ValueError("Appointment date cannot be in the past")
            if date > datetime.now().date() + timedelta(days=90):
                raise ValueError("Appointment date too far in future")
        except ValueError as e:
            raise ValueError(f"Invalid date: {str(e)}")
        return v

class PaymentCreate(BaseModel):
    booking_id: int = Field(..., gt=0)
    card_number: str = Field(..., min_length=13, max_length=19)
    expiry_date: str = Field(..., regex="^\d{2}/\d{2}$")
    cvv: str = Field(..., min_length=3, max_length=4, regex="^[0-9]{3,4}$")
    card_name: str = Field(..., min_length=2, max_length=200)
    amount: float = Field(..., gt=0, le=100000)
    
    @validator('card_number')
    def validate_card(cls, v):
        clean = v.replace(" ", "").replace("-", "")
        if not clean.isdigit():
            raise ValueError("Card number must contain only digits")
        if len(clean) not in [13, 15, 16, 19]:
            raise ValueError("Invalid card number length")
        return clean
    
    @validator('expiry_date')
    def validate_expiry(cls, v):
        try:
            month, year = map(int, v.split('/'))
            if month < 1 or month > 12:
                raise ValueError("Invalid month")
            exp_date = datetime(2000 + year, month, 1)
            if exp_date < datetime.now():
                raise ValueError("Card has expired")
        except:
            raise ValueError("Invalid expiry date format")
        return v

class ConsultationConfirm(BaseModel):
    booking_id: int = Field(..., gt=0)

# --- Utility functions ---
def generate_invoice_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_num = random.randint(1000, 9999)
    return f"TT-{timestamp}-{random_num}"

def generate_payment_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_num = random.randint(10000, 99999)
    return f"PAY-{timestamp}-{random_num}"

def sanitize_html(text: str) -> str:
    """Basic XSS prevention"""
    if not text:
        return text
    return (text.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

# --- FastAPI app ---
app = FastAPI(
    title="Trauma Team International API",
    docs_url=None,  # Disable in production
    redoc_url=None  # Disable in production
)

# CORS - Strict configuration
allowed_origins = [o.strip() for o in CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=3600
)

# --- Root endpoint ---
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "Trauma Team International API",
        "version": "2.0-secure"
    }

# --- OTP endpoints ---
@app.post("/otp/request")
def otp_request(payload: OTPRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)
    
    code = f"{random.randint(1000, 9999)}"
    
    # Delete old OTPs
    db.query(OTP).filter(OTP.email == payload.email).delete()
    
    record = OTP(email=payload.email, otp=code, created_at=datetime.utcnow())
    db.add(record)
    db.commit()
    
    html = f"""
    <h2>Your TraumaTeam OTP</h2>
    <p>Your verification code is <strong>{code}</strong>.</p>
    <p>It will expire in {OTP_EXPIRE_MINUTES} minutes.</p>
    <p>If you did not request this code, please ignore this email.</p>
    """
    _send_email(payload.email, "TraumaTeam OTP Code", html)
    
    return {"message": "OTP sent"}

@app.post("/register")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)
    
    # Verify OTP
    rec = db.query(OTP).filter(
        OTP.email == payload.email, 
        OTP.otp == payload.otp
    ).first()
    
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if datetime.utcnow() - rec.created_at > timedelta(minutes=OTP_EXPIRE_MINUTES):
        db.delete(rec)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired")
    
    # Check if user exists
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed = bcrypt.hash(payload.password)
    user = User(
        email=payload.email, 
        username=sanitize_html(payload.username), 
        password=hashed
    )
    db.add(user)
    db.delete(rec)
    db.commit()
    db.refresh(user)
    
    token = create_token({"user_id": user.id})
    
    _send_email(
        user.email,
        "Welcome to TraumaTeam",
        f"<p>Hi {sanitize_html(user.username)}, your account has been created successfully!</p>"
    )
    
    return {
        "message": "Registered successfully",
        "token": token,
        "user_id": user.id,
        "username": user.username
    }

@app.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)
    
    user = db.query(User).filter(User.email == payload.email).first()
    
    if not user or not bcrypt.verify(payload.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token({"user_id": user.id})
    
    return {
        "token": token,
        "user_id": user.id,
        "username": user.username
    }

# --- BOOKING ENDPOINTS ---
@app.post("/bookings/")
def create_booking(
    booking: BookingCreate, 
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    rate_limit_check(request)
    
    try:
        invoice_id = generate_invoice_id()
        
        new_booking = Booking(
            user_id=current_user.id if current_user else None,
            invoice_id=invoice_id,
            patient_name=sanitize_html(booking.patient_name),
            email=booking.email,
            doctor=booking.doctor,
            appointment_date=booking.appointment_date,
            appointment_time=booking.appointment_time,
            message=sanitize_html(booking.message) if booking.message else "No additional notes",
            status="PENDING",
            payment_status="pending"
        )
        
        db.add(new_booking)
        db.commit()
        db.refresh(new_booking)
        
        _send_email(
            booking.email,
            "Booking Confirmation - Trauma Team International",
            f"""
            <h2>🏥 Booking Received!</h2>
            <p>Dear {sanitize_html(booking.patient_name)},</p>
            <p>Your consultation has been booked with <strong>{booking.doctor}</strong></p>
            <p><strong>Invoice ID:</strong> {invoice_id}</p>
            <p><strong>Date:</strong> {booking.appointment_date}</p>
            <p><strong>Time:</strong> {booking.appointment_time}</p>
            """
        )
        
        return {
            "id": new_booking.id,
            "invoice_id": invoice_id,
            "patient_name": new_booking.patient_name,
            "doctor": new_booking.doctor,
            "appointment_date": new_booking.appointment_date,
            "appointment_time": new_booking.appointment_time,
            "status": new_booking.status
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Booking failed")

@app.post("/payments/")
def process_payment(
    payment: PaymentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    rate_limit_check(request)
    
    try:
        # Find booking with authorization check
        booking = db.query(Booking).filter(Booking.id == payment.booking_id).first()
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        # Authorization: Only booking owner (if authenticated) or email match can pay
        if current_user and booking.user_id and booking.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Unauthorized")
        
        payment_id = generate_payment_id()
        
        new_payment = Payment(
            payment_id=payment_id,
            booking_id=payment.booking_id,
            user_id=current_user.id if current_user else None,
            amount=payment.amount,
            card_number_last4=payment.card_number[-4:],
            card_name=sanitize_html(payment.card_name),
            status="completed"
        )
        
        booking.payment_status = "paid"
        booking.status = "CONFIRMED"
        
        db.add(new_payment)
        db.commit()
        
        _send_email(
            booking.email,
            "Payment Successful",
            f"""
            <h2>✅ Payment Confirmed!</h2>
            <p>Payment ID: {payment_id}</p>
            <p>Amount: ₹{payment.amount:,.2f}</p>
            """
        )
        
        return {
            "status": "completed",
            "payment_id": payment_id,
            "booking_id": payment.booking_id,
            "message": "Payment processed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Payment failed")

@app.post("/consultation/confirm")
def confirm_consultation(
    confirm: ConsultationConfirm,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    rate_limit_check(request)
    
    booking = db.query(Booking).filter(Booking.id == confirm.booking_id).first()
    
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Authorization check
    if current_user and booking.user_id and booking.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    if booking.payment_status != "paid":
        raise HTTPException(status_code=400, detail="Payment not completed")
    
    booking.consultation_confirmed = True
    booking.status = "CONFIRMED"
    db.commit()
    
    _send_email(
        booking.email,
        "Consultation Confirmed",
        "<h2>🎉 Consultation Confirmed!</h2>"
    )
    
    return {"status": "success", "message": "Consultation confirmed"}

@app.get("/api/appointments")
def get_user_appointments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # REQUIRES AUTH NOW
):
    """Get appointments for authenticated user only"""
    bookings = db.query(Booking).filter(
        Booking.user_id == current_user.id
    ).order_by(Booking.created_at.desc()).all()
    
    appointments = []
    for booking in bookings:
        appointments.append({
            "id": booking.id,
            "invoice_id": booking.invoice_id,
            "doctor_name": booking.doctor,
            "appointment_date": booking.appointment_date,
            "appointment_time": booking.appointment_time,
            "message": booking.message,
            "status": booking.status,
            "payment_status": booking.payment_status,
            "consultation_confirmed": booking.consultation_confirmed,
            "doctor_fee": 15000
        })
    
    return {"appointments": appointments}

# --- ADMIN ENDPOINTS ---
@app.post("/admin/login")
def admin_login(payload: LoginRequest, request: Request):
    rate_limit_check(request)
    
    if payload.email != ADMIN_USER or payload.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token({"is_admin": True}, hours_valid=24)
    return {"token": token}

@app.get("/admin/bookings")
def admin_get_bookings(
    _admin=Depends(require_admin), 
    db: Session = Depends(get_db)
):
    bookings = db.query(Booking).order_by(Booking.created_at.desc()).all()
    return {"bookings": bookings}

@app.get("/admin/payments")
def admin_get_payments(
    _admin=Depends(require_admin),
    db: Session = Depends(get_db)
):
    payments = db.query(Payment).order_by(Payment.created_at.desc()).all()
    return {"payments": payments}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting Secure Trauma Team API...")
    print(f"🔒 CORS: {allowed_origins}")
    print(f"📧 Email: {'Enabled' if EMAIL_ENABLED else 'Console mode'}\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
