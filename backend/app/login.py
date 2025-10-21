# -------------------------------------------------------------
#  LOGIN & REGISTRATION
#  This module exposes two endpoints:
#    POST /auth/register  → Create a user + return JWT
#    POST /auth/login     → Authenticate + return JWT
#  We use FastAPI's decorator syntax (@router.post) to register
#  10/21/2025 last update
# -------------------------------------------------------------

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

# Helper to mint JWT access tokens ( for authorize.py)
from .authorize import create_access_token
# Database session and User model (for routes/database.py)
from .routes.database import get_db, User

# Create router that will later be included in app/main.py
#   app.include_router(router, prefix="/auth", tags=["auth"])
router = APIRouter()


# =========================
#  Request/Response Models
# =========================

class UserCreate(BaseModel):
    """
    Payload for register/login requests.
    - FastAPI/Pydantic will validate email format automatically.
    - Password arrives as plaintext (we hash it before storing).
    """
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    """
    Standard bearer-token response payload.
    """
    access_token: str
    token_type: str = "bearer"


# =========================
#  Small Utility
# =========================

def normalize_email(email: str) -> str:
    """
    Normalize email to avoid duplicates with different casing/spacing.
    Example: ' User@Example.com ' → 'user@example.com'
    """
    return email.strip().lower()


# =========================
#  REGISTER
# =========================

@router.post(
    "/register",
    response_model=TokenOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user and return an access token",
)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """
    Flow:
      1) Normalize the email for consistency
      2) Check if email is already in use (quick path)
      3) Hash the password
      4) Insert user and commit
      5) If a race causes duplicate: catch IntegrityError, 409
      6) Create a JWT token tied to the user's id
      7) Return token in a standard shape
    """

    # 1) Normalize email input
    email = normalize_email(payload.email)

    # 2) Pre-check for an existing user (helps return a nice error quickly)
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # 3) Hash the password using passlib's bcrypt
    hashed = bcrypt.hash(payload.password)

    # 4) Create and add the user row
    user = User(email=email, password_hash=hashed)
    db.add(user)

    # 5) Commit and handle a possible duplicate email race
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Load DB-generated fields
    db.refresh(user)

    # 6) Mint a JWT access token with the user's id as the subject
    token = create_access_token(sub=str(user.id))

    # 7) Return the token payload
    return {"access_token": token, "token_type": "bearer"}


# =========================
#  LOGIN
# =========================

@router.post(
    "/login",
    response_model=TokenOut,
    summary="Authenticate with email/password and get an access token",
)
def login(payload: UserCreate, db: Session = Depends(get_db)):
    """
    Flow:
      1) Normalize email
      2) Fetch the user row (if none → generic 401)
      3) Verify the password hash with passlib (if mismatch → generic 401)
      4) Create JWT with the user's id as subject
      5) Return token in a standard shape
    """

    # 1) Normalize input to match storage
    email = normalize_email(payload.email)

    # 2) Look up user by email, return a generic error if not found
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Generic message prevents account enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 3) Verify password using bcrypt, reject on mismatch
    if not bcrypt.verify(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 4) Password ok, then mint a fresh JWT
    token = create_access_token(sub=str(user.id))

    # 5) Return standard token payload
    return {"access_token": token, "token_type": "bearer"}


# =========================
#  HOW THIS GETS MOUNTED
# =========================
# In app/main.py, include this router:
#
#   from .login import router as auth_router
#   app.include_router(auth_router, prefix="/auth", tags=["auth"])
#
# That produces the final paths:
#   POST /auth/register
#   POST /auth/login
