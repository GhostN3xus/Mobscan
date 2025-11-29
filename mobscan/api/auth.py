"""
Authentication and authorization module for Mobscan API.

This module handles JWT token generation, password hashing, and
permission validation.
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import os
import logging

from mobscan.models.db_models import User, APIKey
from mobscan.api.schemas import TokenData

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production-123456")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRY_MINUTES", 30))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password matches, False otherwise
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token.

    Args:
        data: Data to encode in token
        expires_delta: Custom expiration time

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": datetime.utcnow()})

    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating token: {e}")
        raise


def verify_token(token: str) -> Optional[TokenData]:
    """Verify and decode a JWT token.

    Args:
        token: JWT token to verify

    Returns:
        TokenData if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            return None

        token_scopes = payload.get("scopes", [])
        return TokenData(sub=username, scopes=token_scopes)

    except JWTError as e:
        logger.error(f"Invalid token: {e}")
        return None


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password.

    Args:
        db: Database session
        username: Username
        password: Plain text password

    Returns:
        User object if authentication successful, None otherwise
    """
    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            logger.warning(f"User not found: {username}")
            return None

        if not user.is_active:
            logger.warning(f"User inactive: {username}")
            return None

        if not verify_password(password, user.hashed_password):
            logger.warning(f"Invalid password for user: {username}")
            return None

        return user

    except Exception as e:
        logger.error(f"Error authenticating user: {e}")
        return None


def create_user(
    db: Session,
    username: str,
    email: str,
    password: str,
    is_admin: bool = False
) -> Optional[User]:
    """Create a new user.

    Args:
        db: Database session
        username: Username
        email: Email address
        password: Plain text password
        is_admin: Whether user is admin

    Returns:
        Created User object, or None if creation failed
    """
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            logger.warning(f"User already exists: {username}")
            return None

        # Create new user
        hashed_password = hash_password(password)
        new_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_admin=is_admin
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(f"User created successfully: {username}")
        return new_user

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating user: {e}")
        return None


def validate_api_key(db: Session, api_key: str) -> Optional[User]:
    """Validate an API key and return associated user.

    Args:
        db: Database session
        api_key: API key to validate

    Returns:
        User object if valid, None otherwise
    """
    try:
        # Hash the provided key to compare with stored hash
        # In production, you'd store a hash of the API key
        # For now, we'll do simple lookup (not recommended for production)

        api_key_obj = db.query(APIKey).filter(
            APIKey.key_hash == api_key,
            APIKey.is_active == True
        ).first()

        if not api_key_obj:
            logger.warning("Invalid API key")
            return None

        # Update last used timestamp
        api_key_obj.last_used = datetime.utcnow()
        db.commit()

        # Get associated user
        user = db.query(User).filter(User.id == api_key_obj.user_id).first()

        if not user or not user.is_active:
            logger.warning(f"User associated with API key not found or inactive")
            return None

        return user

    except Exception as e:
        logger.error(f"Error validating API key: {e}")
        return None


def create_api_key(db: Session, user_id: int, name: str) -> Optional[str]:
    """Create a new API key for a user.

    Args:
        db: Database session
        user_id: User ID
        name: Name for the API key

    Returns:
        Generated API key, or None if creation failed
    """
    try:
        import secrets

        # Generate random API key
        api_key = secrets.token_urlsafe(32)
        key_hash = hash_password(api_key)

        new_key = APIKey(
            user_id=user_id,
            key_hash=key_hash,
            name=name
        )

        db.add(new_key)
        db.commit()

        logger.info(f"API key created for user {user_id}")
        return api_key

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating API key: {e}")
        return None
