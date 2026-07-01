"""
OAuth2 password-flow + JWT for the gateway.

This is a self-contained demo IdP so the project runs standalone. In a real
deployment, swap `authenticate_user` and `create_access_token` for calls to
a real OAuth2 provider (Okta, Auth0, Keycloak) and just keep the
`decode_and_validate` / `get_current_principal` dependency, which is what
actually protects the gateway's endpoints - the rest of the code doesn't
care where the token came from as long as it's a valid JWT with a `role`
claim.
"""
from __future__ import annotations
import datetime as dt
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from gateway.config import settings
from gateway.models import Principal, Role

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Demo user directory: subject -> (hashed_password, role)
# In production this is a lookup against your identity provider / DB.
_DEMO_USERS = {
    "alice_admin": (pwd_context.hash("admin-pass"), Role.ADMIN),
    "bob_analyst": (pwd_context.hash("analyst-pass"), Role.ANALYST),
    "support_agent_1": (pwd_context.hash("support-pass"), Role.SUPPORT_BOT),
    "eval_agent": (pwd_context.hash("readonly-pass"), Role.READONLY_AGENT),
}


def authenticate_user(username: str, password: str) -> Principal | None:
    record = _DEMO_USERS.get(username)
    if not record:
        return None
    hashed, role = record
    if not pwd_context.verify(password, hashed):
        return None
    return Principal(subject=username, role=role)


def create_access_token(principal: Principal) -> str:
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": principal.subject,
        "role": principal.role.value,
        "exp": expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_and_validate(token: str) -> Principal:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        subject = payload.get("sub")
        role_value = payload.get("role")
        if subject is None or role_value is None:
            raise JWTError("missing sub/role claim")
        return Principal(subject=subject, role=Role(role_value))
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_principal(token: str = Depends(oauth2_scheme)) -> Principal:
    return decode_and_validate(token)
