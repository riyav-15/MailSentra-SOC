import os
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MailSentra SOC"
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    report_dir: str = os.getenv("REPORT_DIR", "generated_reports")
    college_domain: str | None = os.getenv("COLLEGE_DOMAIN", None)
    college_name: str | None = os.getenv("COLLEGE_NAME", None)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify raw password against bcrypt hash."""
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    """Hash password using salted bcrypt Blowfish."""
    return pwd_context.hash(password)


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    """Generate signed JWT access token containing subject (email) and role claim."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc
