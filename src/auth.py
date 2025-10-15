"""
Authentication and User Role Management for Mergington High School Activities
"""

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import hashlib

router = APIRouter()

# In-memory user database (for demo purposes)
users_db = {
    "admin@mergington.edu": {"password": "adminpass", "role": "admin"},
    "staff@mergington.edu": {"password": "staffpass", "role": "staff"},
    "student@mergington.edu": {"password": "studentpass", "role": "student"}
}

class User(BaseModel):
    email: str
    role: str

class UserInDB(User):
    hashed_password: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(email: str, password: str) -> Optional[User]:
    user = users_db.get(email)
    if user and user["password"] == password:
        return User(email=email, role=user["role"])
    return None

@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    # For demo, token is just email
    return {"access_token": user.email, "token_type": "bearer", "role": user.role}

@router.get("/me")
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = users_db.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return User(email=token, role=user["role"])

@router.post("/reset-password")
def reset_password(email: str, new_password: str):
    user = users_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    users_db[email]["password"] = new_password
    return {"message": "Password reset successful"}
