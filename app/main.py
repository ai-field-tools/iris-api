from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.modules.auth.login.routes.login import router as login_router
from app.modules.auth.logout.routes.logout import router as logout_router
from app.modules.auth.token.routes.token import router as token_router
from app.modules.auth.user.routes.user import router as user_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up...")
    yield
    print("Shutting down...")

app = FastAPI(
    title="Iris Classification API",
    description="API for handling login, logout, tokens, and user authentication.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Iris Classification API is running."}

app.include_router(login_router, prefix="/api/auth/login", tags=["Login"])
app.include_router(logout_router, prefix="/api/auth/logout", tags=["Logout"])
app.include_router(token_router, prefix="/api/auth/token", tags=["Token"])
app.include_router(user_router, prefix="/api/auth/users", tags=["User"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
