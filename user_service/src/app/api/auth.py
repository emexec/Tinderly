from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from ..database.crud import UserCRUD
from ..database.sessions import AsyncSession, get_async_session
from ..schemas.forms import FormEmailUpdate, FormPasswordUpdate, FormUserCreate
from ..schemas.schemas import User, UserOut, Token
from ..core.config import settings, PRIVATE_KEY, PUBLIC_KEY

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/token")

router_auth = APIRouter(prefix="/users")

# --- Password Utilities ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- Token Generation ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm="RS256")

def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm="RS256")

# --- Authentication Flow ---
@router_auth.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register_for_tokens(
    response: Response,
    user_form: Annotated[FormUserCreate, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    data = user_form.dict()
    password = data.pop("password")

    existing_user = await UserCRUD.get_by_email(db=session, email=data["email"])
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists."
        )

    hashed_password = get_password_hash(password)
    data["hashed_password"] = hashed_password

    user = await UserCRUD.create(db=session, obj_in=data)

    return UserOut(**user.to_dict())

@router_auth.post("/login", response_model=Token)
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    user = await UserCRUD.get_by_email(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    refresh_token = create_refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/users/refresh"
    )
    return Token(access_token=access_token, token_type="bearer")

@router_auth.post("/refresh", response_model=Token)
async def refresh_token(request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    try:
        payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=["RS256"])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await UserCRUD.get_by_email(session, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer")

@router_auth.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token", path="/users/refresh")
    return {"detail": "Logged out"}

# @router_auth.post("/logout")
# async def logout(response: Response):

# --- Current User Utilities ---
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = await UserCRUD.get_by_email(session, email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
