import os
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    username: str
    role: str # "admin" or "user"
    display_name: str

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    normal_user = os.getenv("USER_USERNAME", "user")
    normal_pass = os.getenv("USER_PASSWORD", "user123")

    uname = request.username.strip()
    pwd = request.password.strip()

    if uname == admin_user and pwd == admin_pass:
        return LoginResponse(
            token="vertex-sec-token-admin-session-active",
            username=admin_user,
            role="admin",
            display_name="SOC Administrator"
        )
    elif uname == normal_user and pwd == normal_pass:
        return LoginResponse(
            token="vertex-sec-token-user-session-active",
            username=normal_user,
            role="user",
            display_name="Security Analyst"
        )
    else:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password. Check credentials in .env file."
        )

@router.get("/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.replace("Bearer ", "")
    if "admin" in token:
        return {"username": os.getenv("ADMIN_USERNAME", "admin"), "role": "admin", "display_name": "SOC Administrator"}
    elif "user" in token:
        return {"username": os.getenv("USER_USERNAME", "user"), "role": "user", "display_name": "Security Analyst"}
    else:
        raise HTTPException(status_code=401, detail="Invalid session token")
