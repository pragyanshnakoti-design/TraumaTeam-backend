# server.py - COMPLETE WORKING BACKEND FOR TRAUMA TEAM

import os
import random
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
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
JWT_SECRET = _env("JWT_SECRET", "trauma_team_secret_key")
DATABASE_URL = _env("DATABASE_URL", "sqlite:///./trauma_team.db")
OTP_EXPIRE_MINUTES = int(_env("OTP_EXPIRE_MINUTES", "5"))
CORS_ORIGINS = _env("CORS_ORIGINS", "*")

# Resend setup (optional - will work without it)
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
        print(f"📧 [EMAIL SIMULATION]")
        print(f"   To: {to}")
        print(f"   Subject: {subject}")
        print(f"   Body: {html[:100]}...")

# --- Database setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
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
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)

class OTP(Base):
    __tablename__ = "otp"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    otp = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Booking(Base):
    """Main booking table for the frontend"""
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(String, unique=True, index=True)
    patient_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    doctor = Column(String, nullable=False)
    appointment_date = Column(String, nullable=False)
    appointment_time = Column(String, nullable=False)
    message = Column(Text)
    status = Column(String, default="PENDING")
    payment_status = Column(String, default="pending")
    consultation_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    """Payment tracking table"""
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    payment_id = Column(String, unique=True, index=True)
    booking_id = Column(String, index=True)
    amount = Column(Float)
    card_number_last4 = Column(String)
    card_name = Column(String)
    status = Column(String, default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

class Appointment(Base):
    """Legacy appointment table for authenticated users"""
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    doctor = Column(String, nullable=False)
    appointment_date = Column(String, nullable=False)
    appointment_time = Column(String, nullable=False)
    message = Column(Text)
    status = Column(String, default="PENDING")

# Create all tables
Base.metadata.create_all(bind=engine)

# --- Auth helpers ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_token(data: dict, hours_valid: int = 8):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=hours_valid)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if not payload or "user_id" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def require_admin(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if not payload or not payload.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return payload

# --- Pydantic Schemas ---
class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class RegisterRequest(BaseModel):
    email: EmailStr
    otp: str
    username: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class BookingCreate(BaseModel):
    patient_name: str
    email: EmailStr
    doctor: str
    appointment_date: str
    appointment_time: str
    message: Optional[str] = None

class PaymentCreate(BaseModel):
    booking_id: str
    card_number: str
    expiry_date: str
    cvv: str
    card_name: str
    amount: float

class ConsultationConfirm(BaseModel):
    booking_id: str

class AppointmentCreate(BaseModel):
    doctor: str
    appointment_date: str
    appointment_time: str
    message: Optional[str] = None

class AdminStatus(BaseModel):
    status: str

# --- Utility functions ---
def generate_invoice_id():
    """Generate unique invoice ID"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_num = random.randint(1000, 9999)
    return f"TT-{timestamp}-{random_num}"

def generate_payment_id():
    """Generate unique payment ID"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_num = random.randint(10000, 99999)
    return f"PAY-{timestamp}-{random_num}"

# --- FastAPI app ---
app = FastAPI(title="Trauma Team International API")

# CORS
origins = [o.strip() for o in (CORS_ORIGINS.split(",") if CORS_ORIGINS else ["*"])]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# --- Root endpoint ---
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "Trauma Team International API",
        "version": "2.0",
        "email_enabled": EMAIL_ENABLED
    }

# --- OTP endpoints (for user registration) ---
@app.post("/otp/request")
def otp_request(payload: OTPRequest, db: Session = Depends(get_db)):
    """Request OTP for email verification"""
    code = f"{random.randint(1000, 9999)}"
    
    # Delete previous OTPs
    db.query(OTP).filter(OTP.email == payload.email).delete()
    
    # Create new OTP
    record = OTP(email=payload.email, otp=code, created_at=datetime.utcnow())
    db.add(record)
    db.commit()
    
    # Send email
    html = f"""
    <h2>Your TraumaTeam OTP</h2>
    <p>Your verification code is <strong>{code}</strong>.</p>
    <p>It will expire in {OTP_EXPIRE_MINUTES} minutes.</p>
    """
    _send_email(payload.email, "TraumaTeam OTP Code", html)
    
    return {"message": "OTP sent (check email)"}

@app.post("/otp/verify")
def otp_verify(payload: OTPVerify, db: Session = Depends(get_db)):
    """Verify OTP without consuming it"""
    rec = db.query(OTP).filter(OTP.email == payload.email, OTP.otp == payload.otp).first()
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if datetime.utcnow() - rec.created_at > timedelta(minutes=OTP_EXPIRE_MINUTES):
        db.delete(rec)
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired")
    
    return {"message": "OTP valid"}

@app.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Register new user with OTP verification"""
    # Check OTP
    rec = db.query(OTP).filter(OTP.email == payload.email, OTP.otp == payload.otp).first()
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
    user = User(email=payload.email, username=payload.username, password=hashed)
    db.add(user)
    db.delete(rec)  # Consume OTP
    db.commit()
    
    # Generate token
    token = create_token({"user_id": user.id})
    
    # Send welcome email
    _send_email(
        user.email,
        "Welcome to TraumaTeam",
        f"<p>Hi {user.username}, your account has been created successfully!</p>"
    )
    
    return {
        "message": "Registered successfully",
        "token": token,
        "user_id": user.id,
        "username": user.username
    }

@app.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """User login"""
    user = db.query(User).filter(User.email == payload.email).first()
    
    if not user or not bcrypt.verify(payload.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token({"user_id": user.id})
    
    return {
        "token": token,
        "user_id": user.id,
        "username": user.username
    }

# --- BOOKING ENDPOINTS (for frontend) ---
@app.post("/bookings/")
def create_booking(booking: BookingCreate, db: Session = Depends(get_db)):
    """Create a new booking (no auth required for frontend)"""
    try:
        # Generate invoice ID
        invoice_id = generate_invoice_id()
        
        # Create booking
        new_booking = Booking(
            invoice_id=invoice_id,
            patient_name=booking.patient_name,
            email=booking.email,
            doctor=booking.doctor,
            appointment_date=booking.appointment_date,
            appointment_time=booking.appointment_time,
            message=booking.message or "No additional notes",
            status="PENDING",
            payment_status="pending"
        )
        
        db.add(new_booking)
        db.commit()
        db.refresh(new_booking)
        
        # Send confirmation email
        _send_email(
            booking.email,
            "Booking Confirmation - Trauma Team International",
            f"""
            <h2>🏥 Booking Received!</h2>
            <p>Dear {booking.patient_name},</p>
            <p>Your consultation has been booked with <strong>{booking.doctor}</strong></p>
            <p><strong>Invoice ID:</strong> {invoice_id}</p>
            <p><strong>Date:</strong> {booking.appointment_date}</p>
            <p><strong>Time:</strong> {booking.appointment_time}</p>
            <p>Please proceed with payment to confirm your appointment.</p>
            <br>
            <p>Trauma Team International</p>
            """
        )
        
        return {
            "id": str(new_booking.id),
            "invoice_id": invoice_id,
            "patient_name": new_booking.patient_name,
            "email": new_booking.email,
            "doctor": new_booking.doctor,
            "appointment_date": new_booking.appointment_date,
            "appointment_time": new_booking.appointment_time,
            "status": new_booking.status,
            "message": "Booking created successfully"
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Booking failed: {str(e)}")

@app.post("/payments/")
def process_payment(payment: PaymentCreate, db: Session = Depends(get_db)):
    """Process payment for a booking"""
    try:
        # Find booking
        booking = db.query(Booking).filter(Booking.id == int(payment.booking_id)).first()
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        # Validate card
        card_clean = payment.card_number.replace(" ", "")
        if len(card_clean) != 16 or not card_clean.isdigit():
            raise HTTPException(status_code=400, detail="Invalid card number")
        
        if len(payment.cvv) != 3 or not payment.cvv.isdigit():
            raise HTTPException(status_code=400, detail="Invalid CVV")
        
        # Generate payment ID
        payment_id = generate_payment_id()
        
        # Create payment record
        new_payment = Payment(
            payment_id=payment_id,
            booking_id=payment.booking_id,
            amount=payment.amount,
            card_number_last4=card_clean[-4:],
            card_name=payment.card_name,
            status="completed"
        )
        
        # Update booking
        booking.payment_status = "paid"
        booking.status = "CONFIRMED"
        
        db.add(new_payment)
        db.commit()
        db.refresh(new_payment)
        
        # Send payment confirmation
        _send_email(
            booking.email,
            "Payment Successful - Trauma Team International",
            f"""
            <h2>✅ Payment Confirmed!</h2>
            <p>Dear {booking.patient_name},</p>
            <p>Your payment of ₹{payment.amount:,.2f} has been processed successfully.</p>
            <p><strong>Payment ID:</strong> {payment_id}</p>
            <p><strong>Invoice ID:</strong> {booking.invoice_id}</p>
            <p><strong>Appointment:</strong> {booking.appointment_date} at {booking.appointment_time}</p>
            <br>
            <p>Trauma Team International</p>
            """
        )
        
        return {
            "status": "completed",
            "payment_id": payment_id,
            "booking_id": payment.booking_id,
            "amount": payment.amount,
            "message": "Payment processed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Payment failed: {str(e)}")

@app.post("/consultation/confirm")
def confirm_consultation(confirm: ConsultationConfirm, db: Session = Depends(get_db)):
    """Confirm a consultation"""
    try:
        # Find booking
        booking = db.query(Booking).filter(Booking.id == int(confirm.booking_id)).first()
        
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        if booking.payment_status != "paid":
            raise HTTPException(status_code=400, detail="Payment not completed")
        
        # Update booking
        booking.consultation_confirmed = True
        booking.status = "CONFIRMED"
        
        db.commit()
        
        # Send final confirmation
        _send_email(
            booking.email,
            "Consultation Confirmed - Trauma Team International",
            f"""
            <h2>🎉 Consultation Confirmed!</h2>
            <p>Dear {booking.patient_name},</p>
            <p>Your consultation with <strong>{booking.doctor}</strong> has been officially confirmed!</p>
            <p><strong>Date:</strong> {booking.appointment_date}</p>
            <p><strong>Time:</strong> {booking.appointment_time}</p>
            <p><strong>Invoice ID:</strong> {booking.invoice_id}</p>
            <br>
            <h3>Next Steps:</h3>
            <ul>
                <li>Our team will contact you 24 hours before</li>
                <li>Please arrive 10 minutes early</li>
                <li>Bring relevant medical records</li>
            </ul>
            <p><strong>Emergency Contact:</strong> +91 98765 43210</p>
            """
        )
        
        return {
            "status": "success",
            "booking_id": confirm.booking_id,
            "message": "Consultation confirmed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Confirmation failed: {str(e)}")

@app.get("/api/appointments")
def get_all_appointments(db: Session = Depends(get_db)):
    """Get all appointments for history view"""
    try:
        bookings = db.query(Booking).order_by(Booking.created_at.desc()).all()
        
        appointments = []
        for booking in bookings:
            appointments.append({
                "id": booking.id,
                "invoice_id": booking.invoice_id,
                "patient_name": booking.patient_name,
                "email": booking.email,
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
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch: {str(e)}")

# --- AUTHENTICATED USER APPOINTMENTS ---
@app.post("/appointments")
def create_appointment(
    payload: AppointmentCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create appointment (requires auth)"""
    appt = Appointment(
        user_id=user.id,
        doctor=payload.doctor,
        appointment_date=payload.appointment_date,
        appointment_time=payload.appointment_time,
        message=payload.message
    )
    db.add(appt)
    db.commit()
    
    _send_email(
        user.email,
        "Appointment Confirmation",
        f"<p>Your appointment with {payload.doctor} is confirmed for {payload.appointment_date} at {payload.appointment_time}</p>"
    )
    
    return {"message": "Appointment created", "id": appt.id}

@app.get("/appointments")
def list_user_appointments(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user appointments (requires auth)"""
    rows = db.query(Appointment).filter(Appointment.user_id == user.id).all()
    return [{
        "id": r.id,
        "doctor": r.doctor,
        "date": r.appointment_date,
        "time": r.appointment_time,
        "message": r.message,
        "status": r.status
    } for r in rows]

# --- ADMIN ENDPOINTS ---
@app.post("/admin/login")
def admin_login(payload: LoginRequest):
    """Admin login"""
    if payload.email != ADMIN_USER or payload.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    token = create_token({"is_admin": True}, hours_valid=24)
    return {"token": token}

@app.get("/admin/appointments")
def admin_list_appointments(_admin=Depends(require_admin), db: Session = Depends(get_db)):
    """List all appointments (admin only)"""
    rows = db.query(Appointment).all()
    return [{
        "id": r.id,
        "user_id": r.user_id,
        "doctor": r.doctor,
        "date": r.appointment_date,
        "time": r.appointment_time,
        "message": r.message,
        "status": r.status
    } for r in rows]

@app.patch("/admin/appointments/{appt_id}")
def admin_update_appointment(
    appt_id: int,
    payload: AdminStatus,
    _admin=Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update appointment status (admin only)"""
    appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    appt.status = payload.status.upper()
    db.commit()
    
    # Notify user
    user = db.query(User).filter(User.id == appt.user_id).first()
    if user:
        _send_email(
            user.email,
            f"Appointment {appt.status}",
            f"<p>Your appointment (ID: {appt.id}) status is now <strong>{appt.status}</strong>.</p>"
        )
    
    return {"message": "Updated", "id": appt.id, "status": appt.status}

@app.get("/admin/bookings")
def admin_get_bookings(_admin=Depends(require_admin), db: Session = Depends(get_db)):
    """Get all bookings (admin only)"""
    bookings = db.query(Booking).order_by(Booking.created_at.desc()).all()
    return {"bookings": bookings}

@app.get("/admin/payments")
def admin_get_payments(_admin=Depends(require_admin), db: Session = Depends(get_db)):
    """Get all payments (admin only)"""
    payments = db.query(Payment).order_by(Payment.created_at.desc()).all()
    return {"payments": payments}

# --- HEALTH CHECK ---
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "email_service": "enabled" if EMAIL_ENABLED else "disabled"
    }

# Run with: uvicorn server:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting Trauma Team International API...")
    print(f"📧 Email service: {'Enabled' if EMAIL_ENABLED else 'Disabled (console mode)'}")
    print("📊 Database: SQLite")
    print("🌐 CORS: Enabled for all origins\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
