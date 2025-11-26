from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
