import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlalchemy.exc import SQLAlchemyError

from ..core.config import settings, PRIVATE_KEY, PUBLIC_KEY
from ..database.crud import UserCRUD
from ..database.sessions import AsyncSession, get_async_session
from ..schemas.forms import FormEmailUpdate, FormPasswordUpdate, FormUserCreate
from ..schemas.schemas import User, UserOut, Token, TokenData, UserInDB
from ..utils.utils import generate_2fa_code
from ..worker import (get_2fa_code_from_redis,
store_2fa_code_in_redis,
send_email_2fa_scheduled,
redis_client)

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


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

@router_auth.post("/register", status_code=status.HTTP_201_CREATED)
async def register_for_2fa(
    user_form: Annotated[FormUserCreate, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
):
    data = user_form.dict()
    password = data.pop("password")

    if await UserCRUD.get_by_email(db=session, email=data["email"]):
        logger.warning(f"Attempt to register with existing email: {data['email']}")
        raise HTTPException(status_code=409, detail="User already exists.")

    hashed_password = get_password_hash(password)
    data["hashed_password"] = hashed_password

    data["is_verified"] = False
    user = await UserCRUD.create(db=session, obj_in=data)

    code = generate_2fa_code()

    store_2fa_code_in_redis(email=user.email, code=code)

    send_email_2fa_scheduled.delay(user.email, code)

    logger.info(f"User registered (pending verification): {user.email}")

    return {"detail": "Check your email for a verification code"}

@router_auth.post("/verify-2fa", response_model=Token)
async def verify_2fa_code(
    email: EmailStr,
    code: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    response: Response
):
    stored_code = get_2fa_code_from_redis(email)

    if not stored_code or str(stored_code).strip() != code.strip():
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")

    user = await UserCRUD.get_by_email(db=session, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        raise HTTPException(status_code=400, detail="User already verified")

    await UserCRUD.update(
            db=session,
            id=user.id,
            obj_in={"is_verified": True}
        )
    redis_client.delete(f"2fa:{email}")

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    refresh_token = create_refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=True, samesite="strict", path="/users/refresh"
    )

    return Token(access_token=access_token, token_type="bearer")

@router_auth.post("/token", response_model=Token)
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    user = await UserCRUD.get_by_email(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Invalid login attempt: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    logger.info(f"User logged in: {user.email}")

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    refresh_token = create_refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=True, samesite="strict", path="/users/refresh"
    )

    return Token(access_token=access_token, token_type="bearer")


@router_auth.post("/refresh", response_model=Token)
async def refresh_token(request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        logger.warning("Missing refresh token in request")
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=["RS256"])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except InvalidTokenError as e:
        logger.error(f"Invalid refresh token: {e}")
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await UserCRUD.get_by_email(session, email)
    if not user:
        logger.error(f"User not found during token refresh: {email}")
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Token refreshed for: {email}")
    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return Token(access_token=access_token, token_type="bearer")


@router_auth.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token", path="/users/refresh")
    logger.info("User logged out")
    return {"detail": "Logged out"}


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        email = payload.get("sub")
        if not email:
            raise credentials_exception
        token_data = TokenData(email=email)
    except InvalidTokenError as e:
        logger.warning(f"Token decode failed: {e}")
        raise credentials_exception

    user = await UserCRUD.get_by_email(db=session, email=token_data.email)
    if user is None:
        logger.warning(f"User not found in get_current_user: {token_data.email}")
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if not current_user.is_active:
        logger.warning(f"Inactive user tried to access resource: {current_user.email}")
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@router_auth.get("/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    logger.info(f"User data retrieved: {current_user.email}")
    return User(**current_user.to_dict())


@router_auth.post("/update/password", response_model=UserOut)
async def update_password(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    user_update_form: Annotated[FormPasswordUpdate, Form()],
    token_payload: Annotated[UserInDB, Depends(get_current_active_user)]
):
    user = await UserCRUD.get_by_email(db=session, email=token_payload.sub)
    if not user:
        logger.warning(f"User not found in update_password: {token_payload.sub}")
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(user_update_form.password, user.hashed_password):
        logger.warning(f"Incorrect current password for: {user.email}")
        raise HTTPException(status_code=403, detail="Password incorrect")

    try:
        updated_user = await UserCRUD.update(
            db=session,
            id=user.id,
            obj_in={"hashed_password": get_password_hash(user_update_form.new_password)}
        )
    except SQLAlchemyError as e:
        logger.error(f"Password update failed for {user.email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update password")

    logger.info(f"Password updated for user: {user.email}")
    return UserOut(**updated_user.to_dict())


@router_auth.post("/update/email", response_model=UserOut)
async def update_email(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    user_update_form: Annotated[FormEmailUpdate, Form()],
    token_payload: Annotated[UserInDB, Depends(get_current_active_user)]
):
    user = await UserCRUD.get_by_email(db=session, email=token_payload.sub)
    if not user:
        logger.warning(f"User not found in update_email: {token_payload.sub}")
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(user_update_form.password, user.hashed_password):
        logger.warning(f"Incorrect password for email update: {user.email}")
        raise HTTPException(status_code=403, detail="Password incorrect")

    existing = await UserCRUD.get_by_email(db=session, email=user_update_form.new_email)
    if existing and existing.id != user.id:
        logger.warning(f"Email already in use: {user_update_form.new_email}")
        raise HTTPException(status_code=409, detail="New email is already in use")

    try:
        updated_user = await UserCRUD.update(
            db=session,
            id=user.id,
            obj_in={"email": user_update_form.new_email}
        )
    except SQLAlchemyError as e:
        logger.error(f"Email update failed for {user.email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update email")

    logger.info(f"Email updated for user: {user.email}")
    return UserOut(**updated_user.to_dict())
