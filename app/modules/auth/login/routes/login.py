"""
FastAPI authentication endpoints with login, token refresh, and user information.

Endpoints:
- POST /auth/login: User authentication with rate limiting
- POST /auth/refresh: Token refresh using refresh token
- GET /auth/me: Current user information

Dependencies: FastAPI, SQLAlchemy, JWT tokens
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import timedelta

from ..services.login import LoginService
from ..schemas.login import (
    LoginRequest,
    LoginResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
)
from ....core.database import get_db
from ....core.config import settings
from ....core.security import get_current_user

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest, http_request: Request, db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.

    Args:
        request: Login credentials (username/email and password)
        http_request: FastAPI request object for client IP
        db: Database session

    Returns:
        LoginResponse with access/refresh tokens and user info

    Raises:
        HTTPException: 429 for rate limiting, 401 for invalid credentials
    """
    login_service = LoginService(db)
    client_ip = http_request.client.host

    # Check rate limiting for login attempts
    if not login_service.validate_login_attempt(request.username, client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )

    # Authenticate user credentials
    user = login_service.authenticate_user(request.username, request.password)

    if not user:
        # Record failed attempt for rate limiting
        login_service.record_failed_login(request.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reset failed attempts on successful login
    login_service.reset_failed_login_attempts(user)

    # Generate JWT tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = login_service.create_access_token(user, access_token_expires)
    refresh_token = login_service.create_refresh_token(user)

    user_info = login_service.get_user_info(user)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_info,
    )


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(request: TokenRefreshRequest, db: Session = Depends(get_db)):
    """
    Generate new access token using valid refresh token.

    Args:
        request: Token refresh request containing refresh token
        db: Database session

    Returns:
        New access token with expiration info

    Raises:
        HTTPException: 401 for invalid refresh token
    """
    login_service = LoginService(db)

    # Verify refresh token and get associated user
    user = login_service.verify_refresh_token(request.refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    # Generate new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = login_service.create_access_token(user, access_token_expires)

    return TokenRefreshResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me")
async def get_current_user_info(
    db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    """
    Get authenticated user's information from JWT token.

    Args:
        db: Database session
        current_user: User extracted from JWT token

    Returns:
        Current user's information
    """
    login_service = LoginService(db)
    return login_service.get_user_info(current_user)
