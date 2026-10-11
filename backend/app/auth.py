from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .security import settings


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
    description="JWT Bearer token acquired via /auth/login",
)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Validate bearer JWT token and return active user model."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        email: str | None = payload.get("sub")
        if not email:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    user = db.query(User).filter(User.email == email.lower()).first()
    if not user:
        raise credentials_exception
    return user


def require_roles(*roles: str) -> Callable[[User], User]:
    """Enforce Role-Based Access Control (RBAC) across employee, analyst, and admin."""
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{current_user.role}' lacks permissions for this endpoint.",
            )
        return current_user

    return dependency


# Role-specific dependency shortcuts for protected routes
require_admin = require_roles("admin")
require_analyst = require_roles("analyst", "admin")
require_employee = require_roles("employee", "analyst", "admin")
