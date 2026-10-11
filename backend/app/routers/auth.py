from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_admin, require_analyst
from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, Token, UserCreate, UserPublic
from ..security import create_access_token, get_password_hash, verify_password
from ..services.audit_logger import log_action

router = APIRouter(prefix="/auth", tags=["Authentication & User Roles"])


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Register a new user account with default 'employee' role."""
    clean_email = payload.email.lower().strip()
    existing = db.query(User).filter(User.email == clean_email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists",
        )

    user = User(
        name=payload.name.strip(),
        email=clean_email,
        password_hash=get_password_hash(payload.password),
        role="employee",
    )
    db.add(user)
    db.flush()
    log_action(db, user.id, "user_registered", f"New employee account registered for {user.email}")
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user with email and password; returns JWT access token."""
    clean_email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == clean_email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(subject=user.email, role=user.role)
    log_action(db, user.id, "user_login", f"{user.email} successfully logged in")
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user,
    }


@router.get("/me", response_model=UserPublic)
def get_current_authenticated_user(current_user: User = Depends(get_current_user)):
    """Get profile details and role for currently logged in user."""
    return current_user
