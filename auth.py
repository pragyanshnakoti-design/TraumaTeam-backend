from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.otp_service import send_otp_and_create_account
from services.otp_service import verify_otp_and_login
from fastapi import Depends
from services.otp_service import credential_login

router = APIRouter(prefix="/api/auth", tags=["Auth"])


class OTPRequest(BaseModel):
    email: str


class OTPVerifyRequest(BaseModel):
    email: str
    otp: str


class CredLoginRequest(BaseModel):
    user_id: str
    password: str


@router.post("/request-otp")
async def request_otp(payload: OTPRequest):
    success, message = await send_otp_and_create_account(payload.email)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"message": message}


@router.post("/verify-otp")
async def verify_otp(payload: OTPVerifyRequest):
    success, result = await verify_otp_and_login(payload.email, payload.otp)
    if not success:
        raise HTTPException(status_code=400, detail=result)
    return result   # contains access_token, temp password, user data


@router.post("/login")
async def login(payload: CredLoginRequest):
    success, result = await credential_login(payload.user_id, payload.password)
    if not success:
        raise HTTPException(status_code=400, detail=result)
    return result
