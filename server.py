# server.py - SECURE BACKEND FOR TRAUMA TEAM (PATCHED FOR PYDANTIC 2.x) - FIXED VERSION

import os
import random
import re
from datetime import datetime, timedelta
from typing import Optional, List

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
    v = os.getenv(key, default)
    if v is None:
        return default
    return v.strip().replace('"', '').replace("'", "")

# Config - FIXED: Allow all origins for now
RESEND_API_KEY = _env("RESEND_API_KEY")
RESEND_FROM = _env("RESEND_FROM", "onboarding@resend.dev")
ADMIN_USER = _env("ADMIN_USER", "admin@trauma.com")
ADMIN_PASS = _env("ADMIN_PASS", "admin123")
JWT_SECRET = _env("JWT_SECRET", "trauma_team_secret_key_CHANGE_IN_PRODUCTION")
DATABASE_URL = _env("DATABASE_URL", "sqlite:///./trauma_team.db")
OTP_EXPIRE_MINUTES = int(_env("OTP_EXPIRE_MINUTES", "5"))
# FIXED: Allow all origins for development
CORS_ORIGINS = _env("CORS_ORIGINS", "*")

# Rate limit
RATE_LIMIT_PER_MINUTE = 50  # Increased for testing
request_counts = {}

# Resend
EMAIL_ENABLED = False
if RESEND_API_KEY:
    try:
        import resend
        resend.api_key = RESEND_API_KEY
        EMAIL_ENABLED = True
        print("✅ Email service enabled")
    except Exception as e:
        print("⚠️ Resend error:", e)
else:
    print("⚠️ Email disabled (No API key)")

def _send_email(to: str, subject: str, html: str):
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
            print(f"📧 Email sent to {to}")
        except Exception as e:
            print("❌ Email error:", e)
    else:
        print(f"[EMAIL SIMULATION] To: {to} -- {subject}")

# Database
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
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

# MODELS
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    username = Column(String(100))
    password = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

class OTP(Base):
    __tablename__ = "otp"
    id = Column(Integer, primary_key=True)
    email = Column(String(255))
    otp = Column(String(10))
    created_at = Column(DateTime, default=datetime.utcnow)
    attempts = Column(Integer, default=0)

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    invoice_id = Column(String(50), unique=True)
    patient_name = Column(String(200))
    email = Column(String(255))
    doctor = Column(String(100))
    appointment_date = Column(String(20))
    appointment_time = Column(String(10))
    message = Column(Text)
    status = Column(String(20), default="PENDING")
    payment_status = Column(String(20), default="pending")
    consultation_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True)
    payment_id = Column(String(50), unique=True)
    booking_id = Column(Integer)
    user_id = Column(Integer, nullable=True)
    amount = Column(Float)
    card_number_last4 = Column(String(4))
    card_name = Column(String(200))
    status = Column(String(20), default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- Rate limiting middleware & helpers ---
from fastapi import Response

def rate_limit_check(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    current_minute = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
    key = f"{client_ip}:{current_minute}"

    # initialize counter
    request_counts.setdefault(key, 0)
    request_counts[key] += 1

    if request_counts[key] > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")

    # cleanup older keys (keep tiny memory)
    for k in list(request_counts.keys()):
        # key format IP:YYYY-MM-DD-HH-MM
        try:
            if k.split(":")[1] != current_minute:
                del request_counts[k]
        except Exception:
            pass

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
    except Exception:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    
    # Check for admin token first
    if payload.get("is_admin"):
        # Return a fake user object for admin
        class AdminUser:
            id = 0
            email = "admin@trauma.com"
            username = "admin"
        return AdminUser()
    
    # Regular user token
    if "user_id" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def get_optional_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    
    # Check for admin token
    if payload.get("is_admin"):
        class AdminUser:
            id = 0
            email = "admin@trauma.com"
            username = "admin"
        return AdminUser()
    
    if "user_id" not in payload:
        return None
    return db.query(User).filter(User.id == payload["user_id"]).first()

def require_admin(token: str = Depends(oauth2_scheme)):
    """FIXED: Admin authentication that works with frontend"""
    if not token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    payload = decode_token(token)
    if not payload or not payload.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return payload

# --- Input validation schemas (Pydantic 2.x compatible) ---
class OTPRequest(BaseModel):
    email: EmailStr

class RegisterRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=4, pattern=r"^[0-9]{4}$")
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)

    @validator("username")
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v

    @validator("password")
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=100)

class BookingCreate(BaseModel):
    patient_name: str = Field(..., min_length=2, max_length=200)
    email: EmailStr
    doctor: str = Field(..., min_length=1, max_length=100)
    appointment_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    appointment_time: str = Field(..., pattern=r"^\d{2}:\d{2}$")
    message: Optional[str] = Field(None, max_length=1000)

    @validator("doctor")
    def validate_doctor(cls, v):
        allowed_doctors = ["Dr. R. Sharma", "Dr. M. Gupta", "Dr. Jyoti"]
        if v not in allowed_doctors:
            raise ValueError("Invalid doctor selection")
        return v

    @validator("appointment_date")
    def validate_date(cls, v):
        try:
            date = datetime.strptime(v, "%Y-%m-%d").date()
            if date < datetime.utcnow().date():
                raise ValueError("Appointment date cannot be in the past")
            if date > datetime.utcnow().date() + timedelta(days=90):
                raise ValueError("Appointment date too far in future")
        except Exception as e:
            raise ValueError(f"Invalid date: {str(e)}")
        return v

class PaymentCreate(BaseModel):
    booking_id: int = Field(..., gt=0)
    card_number: str = Field(..., min_length=13, max_length=19)
    expiry_date: str = Field(..., pattern=r"^\d{2}/\d{2}$")
    cvv: str = Field(..., min_length=3, max_length=4, pattern=r"^[0-9]{3,4}$")
    card_name: str = Field(..., min_length=2, max_length=200)
    amount: float = Field(..., gt=0, le=100000)

    @validator("card_number")
    def validate_card(cls, v):
        clean = v.replace(" ", "").replace("-", "")
        if not clean.isdigit():
            raise ValueError("Card number must contain only digits")
        if len(clean) not in [13, 15, 16, 19]:
            raise ValueError("Invalid card number length")
        return clean

    @validator("expiry_date")
    def validate_expiry(cls, v):
        try:
            month, year = map(int, v.split("/"))
            if month < 1 or month > 12:
                raise ValueError("Invalid month")
            exp_date = datetime(2000 + year, month, 1)
            if exp_date < datetime.utcnow():
                raise ValueError("Card has expired")
        except Exception:
            raise ValueError("Invalid expiry date format")
        return v

class ConsultationConfirm(BaseModel):
    booking_id: int = Field(..., gt=0)

# --- Utility functions ---
def generate_invoice_id():
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    rnd = random.randint(1000, 9999)
    return f"TT-{ts}-{rnd}"

def generate_payment_id():
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    rnd = random.randint(10000, 99999)
    return f"PAY-{ts}-{rnd}"

def sanitize_html(text: Optional[str]) -> Optional[str]:
    if text is None:
        return text
    return (text.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

# --- FastAPI app and CORS ---
app = FastAPI(title="Trauma Team International API (patched)")

# FIXED: Proper CORS configuration
allowed_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
print(f"🌐 CORS Origins: {allowed_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in allowed_origins else allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600
)

# --- Root ---
@app.get("/")
def root():
    return {"status": "ok", "service": "Trauma Team International API", "version": "2.0-secure-patched"}

# --- OTP endpoints ---
@app.post("/otp/request")
def otp_request(payload: OTPRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)

    # generate 4-digit OTP
    code = f"{random.randint(1000, 9999):04d}"

    # remove existing OTPs for email
    db.query(OTP).filter(OTP.email == payload.email).delete()

    rec = OTP(email=payload.email, otp=code, created_at=datetime.utcnow(), attempts=0)
    db.add(rec)
    db.commit()

    html = f"""
    <h2>Your TraumaTeam OTP</h2>
    <p>Your verification code is <strong>{code}</strong>.</p>
    <p>It will expire in {OTP_EXPIRE_MINUTES} minutes.</p>
    """

    _send_email(payload.email, "TraumaTeam OTP Code", html)
    return {"message": "OTP sent"}

@app.post("/register")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)

    rec = db.query(OTP).filter(OTP.email == payload.email, OTP.otp == payload.otp).first()
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if datetime.utcnow() - rec.created_at > timedelta(minutes=OTP_EXPIRE_MINUTES):
        db.delete(rec)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired")

    # ensure not already registered
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = bcrypt.hash(payload.password)
    user = User(email=payload.email, username=sanitize_html(payload.username), password=hashed)
    db.add(user)
    db.delete(rec)
    db.commit()
    db.refresh(user)

    token = create_token({"user_id": user.id})
    _send_email(user.email, "Welcome to TraumaTeam", f"<p>Hi {sanitize_html(user.username)}, your account is ready.</p>")

    return {"message": "Registered successfully", "token": token, "user_id": user.id, "username": user.username}

@app.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit_check(request)

    # Check if admin login
    if payload.email == ADMIN_USER and payload.password == ADMIN_PASS:
        token = create_token({"is_admin": True}, hours_valid=24)
        return {"token": token, "user_id": 0, "username": "admin", "is_admin": True}

    # Regular user login
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not bcrypt.verify(payload.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"user_id": user.id})
    return {"token": token, "user_id": user.id, "username": user.username}

# ---------------------------------------------------------
# BOOKING ENDPOINTS - FIXED
# ---------------------------------------------------------
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
            user_id=current_user.id if current_user and hasattr(current_user, 'id') else None,
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

        # send confirmation email
        _send_email(
            booking.email,
            "Booking Received - Trauma Team International",
            f"""
            <h2>🏥 Booking Received!</h2>
            <p>Hello {sanitize_html(booking.patient_name)},</p>
            <p>Your consultation with <strong>{booking.doctor}</strong> has been booked.</p>
            <p><strong>Invoice ID:</strong> {invoice_id}</p>
            <p><strong>Date:</strong> {booking.appointment_date}</p>
            <p><strong>Time:</strong> {booking.appointment_time}</p>
            <p><strong>Status:</strong> Pending confirmation</p>
            <p>Our team will contact you shortly.</p>
            """
        )

        return {
            "id": new_booking.id,
            "invoice_id": invoice_id,
            "patient_name": new_booking.patient_name,
            "email": new_booking.email,
            "doctor": new_booking.doctor,
            "appointment_date": new_booking.appointment_date,
            "appointment_time": new_booking.appointment_time,
            "status": new_booking.status,
            "payment_status": new_booking.payment_status,
            "message": new_booking.message
        }

    except Exception as e:
        print("Booking Error:", e)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Booking failed: {str(e)}")


# ---------------------------------------------------------
# PAYMENT ENDPOINT
# ---------------------------------------------------------
@app.post("/payments/")
def process_payment(
    payment: PaymentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    rate_limit_check(request)

    booking = db.query(Booking).filter(Booking.id == payment.booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    # authorization
    if current_user and hasattr(current_user, 'id') and booking.user_id and booking.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        payment_id = generate_payment_id()

        new_payment = Payment(
            payment_id=payment_id,
            booking_id=payment.booking_id,
            user_id=current_user.id if current_user and hasattr(current_user, 'id') else None,
            amount=payment.amount,
            card_number_last4=payment.card_number[-4:],  # only last 4 digits
            card_name=sanitize_html(payment.card_name),
            status="completed"
        )

        booking.payment_status = "paid"
        booking.status = "CONFIRMED"

        db.add(new_payment)
        db.commit()

        _send_email(
            booking.email,
            "Payment Successful - Trauma Team",
            f"""
            <h2>💳 Payment Successful</h2>
            <p>Payment ID: <strong>{payment_id}</strong></p>
            <p>Amount: ₹{payment.amount:,.2f}</p>
            <p>Booking #{booking.id} has been confirmed.</p>
            """
        )

        return {
            "status": "completed",
            "payment_id": payment_id,
            "booking_id": payment.booking_id,
            "message": "Payment processed successfully",
        }

    except Exception as e:
        print("Payment Error:", e)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Payment failed: {str(e)}")


# ---------------------------------------------------------
# CONSULTATION CONFIRM - FIXED for Admin
# ---------------------------------------------------------
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

    # Check if current_user is admin
    is_admin = False
    if current_user and hasattr(current_user, 'email') and current_user.email == "admin@trauma.com":
        is_admin = True
    
    # If not admin, check authorization
    if not is_admin:
        if current_user and hasattr(current_user, 'id') and booking.user_id and booking.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Unauthorized")
        if booking.payment_status != "paid":
            raise HTTPException(status_code=400, detail="Payment not completed")

    booking.consultation_confirmed = True
    booking.status = "CONFIRMED"
    db.commit()

    _send_email(
        booking.email,
        "Consultation Confirmed - Trauma Team",
        f"""
        <h2>🎉 Your consultation is officially confirmed!</h2>
        <p>Booking #{booking.id} has been confirmed.</p>
        <p><strong>Doctor:</strong> {booking.doctor}</p>
        <p><strong>Date:</strong> {booking.appointment_date}</p>
        <p><strong>Time:</strong> {booking.appointment_time}</p>
        <p>Please arrive 10 minutes before your scheduled time.</p>
        """
    )

    return {"status": "success", "message": "Consultation confirmed", "booking_id": booking.id}


# ---------------------------------------------------------
# USER APPOINTMENTS (AUTH REQUIRED)
# ---------------------------------------------------------
@app.get("/api/appointments")
def get_user_appointments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # If admin, return all appointments
    if hasattr(current_user, 'email') and current_user.email == "admin@trauma.com":
        bookings = db.query(Booking).order_by(Booking.created_at.desc()).all()
    else:
        bookings = (
            db.query(Booking)
            .filter(Booking.user_id == current_user.id)
            .order_by(Booking.created_at.desc())
            .all()
        )

    output = []

    for b in bookings:
        output.append({
            "id": b.id,
            "invoice_id": b.invoice_id,
            "patient_name": b.patient_name,
            "email": b.email,
            "doctor": b.doctor,
            "appointment_date": b.appointment_date,
            "appointment_time": b.appointment_time,
            "message": b.message,
            "status": b.status,
            "payment_status": b.payment_status,
            "consultation_confirmed": b.consultation_confirmed,
            "created_at": b.created_at.isoformat() if b.created_at else None
        })

    return {"appointments": output}


# ---------------------------------------------------------
# ADMIN ENDPOINTS - FIXED
# ---------------------------------------------------------
@app.post("/admin/login")
def admin_login(payload: LoginRequest, request: Request):
    rate_limit_check(request)

    if payload.email != ADMIN_USER or payload.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    token = create_token({"is_admin": True, "email": ADMIN_USER}, hours_valid=24)
    return {
        "token": token, 
        "user_id": 0, 
        "username": "admin", 
        "email": ADMIN_USER,
        "message": "Admin login successful"
    }


@app.get("/admin/bookings")
def admin_get_bookings(_admin=Depends(require_admin), db: Session = Depends(get_db)):
    bookings = db.query(Booking).order_by(Booking.created_at.desc()).all()
    
    # Convert to list of dicts
    bookings_list = []
    for b in bookings:
        bookings_list.append({
            "id": b.id,
            "invoice_id": b.invoice_id,
            "patient_name": b.patient_name,
            "email": b.email,
            "doctor": b.doctor,
            "appointment_date": b.appointment_date,
            "appointment_time": b.appointment_time,
            "message": b.message or "",
            "status": b.status,
            "payment_status": b.payment_status,
            "consultation_confirmed": b.consultation_confirmed,
            "created_at": b.created_at.isoformat() if b.created_at else None
        })
    
    return {"bookings": bookings_list}


@app.get("/admin/payments")
def admin_get_payments(_admin=Depends(require_admin), db: Session = Depends(get_db)):
    payments = db.query(Payment).order_by(Payment.created_at.desc()).all()
    
    payments_list = []
    for p in payments:
        payments_list.append({
            "id": p.id,
            "payment_id": p.payment_id,
            "booking_id": p.booking_id,
            "amount": p.amount,
            "card_last4": p.card_number_last4,
            "card_name": p.card_name,
            "status": p.status,
            "created_at": p.created_at.isoformat() if p.created_at else None
        })
    
    return {"payments": payments_list}


# ---------------------------------------------------------
# TEST ENDPOINTS (for debugging)
# ---------------------------------------------------------
@app.get("/test")
def test_endpoint():
    return {
        "status": "ok",
        "message": "Backend is running",
        "timestamp": datetime.utcnow().isoformat(),
        "admin_user": ADMIN_USER,
        "cors_origins": CORS_ORIGINS
    }

@app.post("/test/booking")
def test_create_booking(booking: BookingCreate, db: Session = Depends(get_db)):
    """Test endpoint to create booking without auth"""
    invoice_id = generate_invoice_id()
    
    new_booking = Booking(
        invoice_id=invoice_id,
        patient_name=booking.patient_name,
        email=booking.email,
        doctor=booking.doctor,
        appointment_date=booking.appointment_date,
        appointment_time=booking.appointment_time,
        message=booking.message or "Test booking"
    )
    
    db.add(new_booking)
    db.commit()
    db.refresh(new_booking)
    
    return {
        "test": True,
        "id": new_booking.id,
        "invoice_id": invoice_id,
        "message": "Test booking created successfully"
    }

# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ---------------------------------------------------------
# RUN SERVER
# ---------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*50)
    print("🚀 Starting Trauma Team API (Patched & Fixed)")
    print(f"📁 Database: {DATABASE_URL}")
    print(f"🌐 CORS: {CORS_ORIGINS}")
    print(f"👑 Admin: {ADMIN_USER}")
    print("="*50 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
