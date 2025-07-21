"""
FastAPI logout endpoint to revoke user refresh tokens.

Endpoints:
- POST /auth/logout: Logout user and revoke refresh token

Dependencies: FastAPI, SQLAlchemy, JWT tokens
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.modules.database.base import get_db
from ....core.security import get_current_user
from ..services.logout import LogoutService
from app.modules.auth.user.models.user import User

router = APIRouter()

@router.post("/logout")
async def logout(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Log out the current user by revoking the refresh token.

    Args:
        request: FastAPI request object (optional metadata)
        db: Database session
        current_user: Authenticated user from JWT token

    Returns:
        Confirmation message

    Raises:
        HTTPException: 401 if user is not authenticated or logout fails
    """
    logout_service = LogoutService(db)

    success = logout_service.revoke_refresh_token(current_user)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Logout failed. Token may already be revoked.",
        )

    return {"message": "Successfully logged out."}
