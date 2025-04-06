# app/utils.py

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from graphql import GraphQLError
from app.db.database import Session
from app.db.models import User
from datetime import datetime, timedelta, timezone
from functools import wraps
from dotenv import load_dotenv
import os
import logging
import re # Import re for password regex checks
from email_validator import validate_email, EmailNotValidError
# --- Import pwnedpasswords ---
import pwnedpasswords


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)


# --- Environment Variable Loading ---
load_dotenv()
ALGORITHM = os.getenv("ALGORITHM", "HS256")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    log.critical("FATAL: SECRET_KEY not found in environment variables!")
    raise ValueError("SECRET_KEY must be set in the environment variables.")
try:
    TOKEN_EXPIRATION_TIME_MINUTES = int(os.getenv("TOKEN_EXPIRATION_TIME_MINUTES", 30))
except ValueError:
    log.warning("Invalid TOKEN_EXPIRATION_TIME_MINUTES in .env, using default 30 minutes.")
    TOKEN_EXPIRATION_TIME_MINUTES = 30


# --- JWT Token Handling ---
def generate_token(email: str) -> str:
    """Generates a JWT token for the given email."""
    log.debug(f"Generating token for email: {email}")
    expiration_time = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRATION_TIME_MINUTES)
    payload = {
        "sub": email,
        "exp": expiration_time,
        "iat": datetime.now(timezone.utc)
    }
    try:
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        log.info(f"Token generated successfully for email: {email}")
        return token
    except Exception as e:
        log.error(f"Error encoding JWT for {email}: {e}", exc_info=True)
        raise GraphQLError("Could not generate token due to an internal server error.")


def get_authenticated_user(context: dict) -> User:
    """Verifies JWT token and returns the User object."""
    log.debug("Attempting to authenticate user from context.")
    request_object = context.get('request')
    if not request_object:
        log.warning("Authentication context missing 'request' object.")
        raise GraphQLError("Authentication context not available.")
    auth_header = request_object.headers.get('Authorization')
    token_prefix = "Bearer "
    if not auth_header or not auth_header.startswith(token_prefix):
        log.warning("Authentication failed: Missing or invalid Authorization header format.")
        raise GraphQLError("Authentication token is missing or invalid.")
    token = auth_header[len(token_prefix):]
    if not token:
        log.warning("Authentication failed: Token part is missing after 'Bearer '.")
        raise GraphQLError("Authentication token is missing.")
    log.debug("Authorization header found, attempting JWT decode.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        log.debug(f"Token decoded successfully. Payload: {payload}")
        user_email = payload.get('sub')
        if not user_email:
            log.warning("Invalid token payload: Missing 'sub' (subject) claim.")
            raise GraphQLError("Invalid token payload.")
        log.debug(f"Fetching user from DB for email: {user_email}")
        with Session() as session:
            user = session.query(User).filter(User.email == user_email).first()
            if not user:
                log.warning(f"User with email {user_email} from valid token not found in DB.")
                raise GraphQLError("Authentication failed.")
            log.info(f"User authenticated successfully: ID={user.id}, Email={user.email}")
            return user
    except jwt.ExpiredSignatureError:
        log.warning("Authentication failed: Token has expired.")
        raise GraphQLError("Token has expired.")
    except jwt.InvalidTokenError as e:
        log.warning(f"Authentication failed: Invalid JWT token - {e}")
        raise GraphQLError("Invalid authentication token.")
    except Exception as e:
        log.error(f"Unexpected error during authentication: {e}", exc_info=True)
        raise GraphQLError("An internal error occurred during authentication.")


# --- Password Handling ---
def hash_password(pwd: str) -> str:
    """Hashes a password using Argon2."""
    ph = PasswordHasher()
    # Basic length validation can be part of is_password_strong
    # No need to repeat here if always checked before hashing
    try:
        log.debug("Hashing password with Argon2.")
        hashed = ph.hash(pwd)
        log.debug("Password hashed successfully.")
        return hashed
    except Exception as e:
        log.error(f"Error hashing password: {e}", exc_info=True)
        raise ValueError("Could not hash password due to internal error.")


def verify_password(pwd_hash: str, pwd: str) -> bool:
    """Verifies a plaintext password against an Argon2 hash."""
    ph = PasswordHasher()
    log.debug("Verifying password hash.")
    try:
        ph.verify(pwd_hash, pwd)
        log.debug("Password verification successful.")
        return True
    except VerifyMismatchError:
        log.warning("Password verification failed: Mismatch.")
        raise GraphQLError("Invalid email or password")
    except (VerificationError, InvalidHash) as e:
        log.error(f"Password verification error: Hash format or verification issue - {e}", exc_info=True)
        raise GraphQLError("Error during password verification process.")
    except Exception as e:
        log.error(f"Unexpected password verification error: {e}", exc_info=True)
        raise GraphQLError("An internal error occurred during password verification.")


# --- Password Policy ---
def is_password_strong(password: str, username: str | None = None, email: str | None = None) -> bool:
    """
    Checks if the password meets security policy requirements.
    Raises ValueError with a user-friendly message if the policy is not met.
    """
    min_length = 8 # Consider making this configurable
    if not password or len(password) < min_length:
        log.warning(f"Password policy violation: Too short (length {len(password) if password else 0}).")
        raise ValueError(f"Password must be at least {min_length} characters long.")

    # --- Character Variety Checks ---
    log.debug("Checking password character variety.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one digit.")
    # Define symbols - adjust set as needed
    symbols = r"[!@#$%^&*(),.?\":{}|<>]"
    if not re.search(symbols, password):
        raise ValueError("Password must contain at least one special character (e.g., !@#$%).")
    log.debug("Password character variety check passed.")

    # --- Check against Username and Email ---
    log.debug("Checking password against username/email.")
    if username and username.lower() in password.lower():
        log.warning("Password policy violation: Contains username.")
        raise ValueError("Password cannot contain your username.")
    if email:
        email_parts = email.split('@')
        if len(email_parts) > 0 and email_parts[0].lower() in password.lower():
            log.warning("Password policy violation: Contains email prefix.")
            raise ValueError("Password cannot contain your email address prefix.")
    log.debug("Password does not contain username/email prefix.")

    # --- Check against Pwned Passwords List ---
    log.debug("Checking password against pwned passwords list.")
    try:
        count = pwnedpasswords.check(password)
        if count > 0:
            log.warning(f"Password policy violation: Found in {count} breaches.")
            raise ValueError(f"This password has appeared in data breaches; please choose a stronger, unique password.")
        log.debug("Password not found in pwned passwords list.")
    except ImportError: # Should not happen if installed, but good practice
        log.error("pwnedpasswords library not installed, cannot check breach status.")
        # Decide: Fail open (allow password) or fail closed (reject)? For security, maybe reject.
        # raise ValueError("Could not check password security status. Please try again later.")
        # Or allow, but log critically:
        log.critical("PWNEDPASSWORDS CHECK SKIPPED - LIBRARY MISSING")
    except Exception as e:
        # Log errors during the check but don't necessarily fail the password attempt
        # unless policy dictates otherwise (e.g., if check is mandatory)
        log.error(f"Error checking pwnedpasswords (network issue?): {e}", exc_info=True)
        # Could raise an error here, or just log and proceed

    # If all checks passed
    log.info("Password passed all policy checks.")
    return True


# --- Email Validation ---
def validate_user_email(email: str) -> str:
    """Validates email format using email-validator. Returns normalized email."""
    if not email:
        raise ValueError("Email address cannot be empty.")
    log.debug(f"Validating email address: {email}")
    try:
        email_info = validate_email(email, check_deliverability=False)
        normalized_email = email_info.normalized
        log.debug(f"Email validated successfully. Normalized: {normalized_email}")
        return normalized_email
    except EmailNotValidError as e:
        log.warning(f"Invalid email format detected for '{email}': {e}")
        raise ValueError(f"Invalid email address format: {str(e)}")
    except Exception as e:
        log.error(f"Unexpected error during email validation for {email}: {e}", exc_info=True)
        raise ValueError("An internal error occurred during email validation.")


# --- Authorization Decorators ---
def admin_user(func):
    """ Decorator: Authenticated user must be an admin. """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if len(args) < 2:
            log.error(f"Decorator '@admin_user' applied incorrectly to function '{func.__name__}' - missing 'info' argument?")
            raise GraphQLError("Internal server error: Authorization setup incorrect.")
        info = args[1]
        user = get_authenticated_user(info.context)
        if user.role != "admin":
            log.warning(f"Authorization failed: User {user.id} is not admin for '{func.__name__}'.")
            raise GraphQLError("You are not authorized to perform this action (Admin required).")
        log.debug(f"Admin access granted for user {user.id} to '{func.__name__}'.")
        return func(*args, **kwargs)
    return wrapper


def authd_user(func):
    """ Decorator: User must be authenticated via JWT. """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if len(args) < 2:
            log.error(f"Decorator '@authd_user' applied incorrectly to function '{func.__name__}' - missing 'info' argument?")
            raise GraphQLError("Internal server error: Authorization setup incorrect.")
        info = args[1]
        get_authenticated_user(info.context) # Raises GraphQLError if auth fails
        log.debug(f"User authenticated for '{func.__name__}'.")
        return func(*args, **kwargs)
    return wrapper