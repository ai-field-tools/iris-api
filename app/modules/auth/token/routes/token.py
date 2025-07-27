"""
FastAPI token management endpoints.

Endpoints:
- POST /auth/token/refresh: Token refresh using refresh token

"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..services.token import TokenService
from ..schemas.token import TokenRefreshRequest, TokenRefreshResponse
from app.modules.database.base import get_db

router = APIRouter()

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
    token_service = TokenService(db)

    # Verify refresh token and get associated user
    user = token_service.verify_refresh_token(request.refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )

    # Generate new access token
    return token_service.create_token_refresh_response(user)