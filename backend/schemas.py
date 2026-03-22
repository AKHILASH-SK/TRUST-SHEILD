from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

# Registration Request
class UserRegisterRequest(BaseModel):
    name: str
    last_name: str
    email: EmailStr
    phone_number: str
    pin: str

class UserRegisterResponse(BaseModel):
    id: int
    name: str
    email: str
    phone_number: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Login Request/Response
class UserLoginRequest(BaseModel):
    phone_number: str
    pin: str

class UserLoginResponse(BaseModel):
    id: int
    name: str
    email: str
    phone_number: str
    message: str = "Login successful"
    
    class Config:
        from_attributes = True

# Link Scan
class LinkScanRequest(BaseModel):
    user_id: int
    url: str

class LinkScanResponse(BaseModel):
    id: int
    user_id: int
    url: str
    risk_level: str
    reasons: Optional[str]
    verdict: Optional[str]
    analyzed_at: datetime
    
    class Config:
        from_attributes = True

# Generic Response
class MessageResponse(BaseModel):
    message: str
    success: bool
