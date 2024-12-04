import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from graphql import GraphQLError
from app.db.database import Session
from app.db.models import User
from datetime import datetime, timedelta, timezone
from functools import wraps
from dotenv import load_dotenv
import os


load_dotenv()
ALGORITHM = os.getenv("ALGORITHM")
SECRET_KEY = os.getenv("SECRET_KEY")
TOKEN_EXPIRATION_TIME_MINUTES = int(os.getenv("TOKEN_EXPIRATION_TIME_MINUTES"))


def generate_token(email):

    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRATION_TIME_MINUTES)

    payload = {
        "sub": email,
        "exp": expiration_time
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def get_authenticated_user(context):
    request_object = context.get('request')
    auth_header = request_object.headers.get('Authorization')

    token = [None]
    if auth_header:
        token = auth_header.split(" ")

    if auth_header and token[0] == "Bearer" and len(token) == 2:
        try:
            payload = jwt.decode(token[1], SECRET_KEY, algorithms=[ALGORITHM])

            if datetime.now(timezone.utc) > datetime.fromtimestamp(payload['exp'], tz=timezone.utc):
                raise GraphQLError("Token has expired")

            session = Session()
            user = session.query(User).filter(User.email == payload.get('sub')).first()

            if not user:
                raise GraphQLError("Could not authenticate user")

            return user

        except jwt.exceptions.PyJWTError:
            raise GraphQLError("Invalid authentication token")
        except Exception as e:
            raise GraphQLError("Something went wrong")

    else:
        raise GraphQLError("Missing authentication token")


def hash_password(pwd):
    ph = PasswordHasher()
    return ph.hash(pwd)


def verify_password(pwd_hash, pwd):
    ph = PasswordHasher()


    try:
        ph.verify(pwd_hash, pwd)

    except VerifyMismatchError:
        raise GraphQLError("Invalid email or password")


def admin_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        info = args[1]
        user = get_authenticated_user(info.context)

        if user.role != "admin":
            raise GraphQLError("You are not authorized to perform this action")

        return func(*args, **kwargs)

    return wrapper


def authd_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        info = args[1]
        get_authenticated_user(info.context)
        return func(*args, **kwargs)
    return wrapper


def authd_user_same_as(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        info = args[1]
        user = get_authenticated_user(info.context)
        uid = kwargs.get("user_id")

        if user.id != uid:
            raise GraphQLError("You are not authorized to perform this action")

        return func(*args, **kwargs)

    return wrapper