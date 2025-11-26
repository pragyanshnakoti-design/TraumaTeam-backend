from datetime import datetime, timezone
from typing import List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware

from config import ADMIN_USERNAME, ADMIN_PASSWORD
from storage import (
    load_appointments,
    save_appointments,
    get_user_by_email,
    save_or_update_user,
    next_appointment_id,
)
from security import get_password_hash, verify_password, create_access_token
from otp import create_and_send_otp, consume_otp, generate_user_id
from schemas import (
    RequestOtp,
    VerifyOtp,
    CredLogin,
    TokenResponse,
    AppointmentCreate,
    AppointmentOut,
    AdminLogin,
)
from deps import get_current_user, get_current_admin

# =========================
# FASTAPI APP
# =========================

app = FastAPI(
    title="Trauma Team Backend",
    description="Secure consultation backend for Trauma Team International",
    version="1.0.0",
)

# CORS: allow all, so browser never gets blocked by CORS
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# BASIC ROUTES
# =========================

@app.get("/")
async def root():
    return {
        "service": "Trauma Team Backend",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/favicon.ico")
async def favicon():
    return {"detail": "no favicon"}


# =========================
# AUTH – OTP
# =========================

@app.post("/auth/request-otp")
async def request_otp(payload: RequestOtp):
    email = payload.email.strip().lower()
    create_and_send_otp(email)
    return {"message": f"OTP sent to {email}. Valid for 10 minutes."}


@app.post("/auth/verify-otp", response_model=TokenResponse)
async def verify_otp(payload: VerifyOtp):
    email = payload.email.strip().lower()
    otp_code = payload.otp.strip()

    # Validate OTP + get temp password
    record = consume_otp(email, otp_code)
    temp_password = record["temp_password"]

    # Create / update user
    user = get_user_by_email(email)
    if not user:
        user_id = generate_user_id()
        password_hash = get_password_hash(temp_password)
        user = {
            "user_id": user_id,
            "email": email,
            "full_name": "",
            "password_hash": password_hash,
            "role": "user",
        }
        save_or_update_user(user)
    else:
        # ensure role + email
        user["email"] = email
        user.setdefault("role", "user")
        save_or_update_user(user)

    # JWT token
    token = create_access_token(
        data={"sub": user["user_id"], "role": user.get("role", "user")}
    )

    return TokenResponse(
        access_token=token,
        user={
            "user_id": user["user_id"],
            "email": user["email"],
            "full_name": user.get("full_name") or email.split("@")[0],
        },
        password=temp_password,
    )


# =========================
# AUTH – CREDENTIAL LOGIN
# =========================

from storage import get_user_by_user_id  # import here to avoid circular

@app.post("/auth/login", response_model=TokenResponse)
async def login_with_credentials(payload: CredLogin):
    user_id = payload.user_id.strip()
    pw = payload.password

    user = get_user_by_user_id(user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid User ID or password.")

    if not verify_password(pw, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid User ID or password.")

    token = create_access_token(
        data={"sub": user["user_id"], "role": user.get("role", "user")}
    )

    return TokenResponse(
        access_token=token,
        user={
            "user_id": user["user_id"],
            "email": user["email"],
            "full_name": user.get("full_name") or user["email"].split("@")[0],
        },
    )


# =========================
# USER APPOINTMENTS
# =========================

@app.post("/appointments")
async def create_appointment(
    payload: AppointmentCreate,
    current_user=Depends(get_current_user),
):
    apps = load_appointments()
    new_id = next_appointment_id()

    email = payload.email or current_user.get("email")

    new_app = {
        "id": new_id,
        "user_id": current_user.get("user_id"),
        "patient_name": payload.patient_name,
        "email": email,
        "doctor_name": payload.doctor_name,
        "appointment_date": payload.appointment_date,
        "appointment_time": payload.appointment_time,
        "message": payload.message or "No additional notes",
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    apps.append(new_app)
    save_appointments(apps)

    return {"message": "Appointment created successfully.", "id": new_id}


@app.get("/appointments/me", response_model=List[AppointmentOut])
async def get_my_appointments(current_user=Depends(get_current_user)):
    apps = load_appointments()
    my = [a for a in apps if a.get("user_id") == current_user.get("user_id")]
    return my


# =========================
# ADMIN ENDPOINTS
# =========================

@app.post("/admin/login", response_model=TokenResponse)
async def admin_login(payload: AdminLogin):
    if payload.username != ADMIN_USERNAME or payload.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=400, detail="Invalid admin credentials.")
    token = create_access_token(data={"sub": "ADMIN", "role": "admin"})
    return TokenResponse(
        access_token=token,
        user={
            "user_id": "ADMIN",
            "email": "admin@traumateam.local",
            "full_name": "Admin",
        },
    )


@app.get("/admin/appointments", response_model=List[AppointmentOut])
async def admin_get_appointments(current_admin=Depends(get_current_admin)):
    apps = load_appointments()
    return apps
