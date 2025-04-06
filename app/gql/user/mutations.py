# app/gql/user/mutations.py

import logging
from sqlalchemy.exc import IntegrityError # For catching DB constraint violations

from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError

# --- Import decorators and utilities ---
from app.utils import (
    generate_token,       # Used in LoginUser
    verify_password,      # Used in LoginUser, UpdateUser
    get_authenticated_user, # Used in AddUser (conditionally), UpdateUser, ApplyToJob, DeleteUser
    hash_password,        # Used in AddUser, UpdateUser
    authd_user,           # Decorator used on UpdateUser, ApplyToJob, DeleteUser
    is_password_strong,   # Use the enhanced policy checker
    validate_user_email   # Use the library-based validator
)

# --- Import DB Session and Models ---
from app.db.database import Session
from app.db.models import User, JobApplication, Job # Job needed for ApplyToJob check

# --- Import GQL Types ---
from app.gql.types import UserObject, JobApplicationObject

# Setup logging for this module
logging.basicConfig(level=logging.INFO) # Ensure basicConfig is called (usually in main app)
log = logging.getLogger(__name__) # Use module-specific logger


class LoginUser(Mutation):
    """ GraphQL Mutation for user login. (Public Access) """
    class Arguments:
        email = String(required=True)
        password = String(required=True)
    token = String()

    @staticmethod
    def mutate(root, info, email, password):
        """Handles user login attempt."""
        log.info(f"Login attempt for email: {email}")
        with Session() as session:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                log.warning(f"Login failed: User not found for email {email}")
                raise GraphQLError("Invalid email or password")
            try:
                log.debug(f"Verifying password for user ID {user.id}")
                verify_password(user.password_hash, password) # Raises GraphQLError
                log.debug(f"Password verified for user ID {user.id}, generating token.")
                token = generate_token(email) # Raises GraphQLError
                log.info(f"Login successful for user ID {user.id}")
                return LoginUser(token=token)
            except GraphQLError as e:
                log.warning(f"Login failed for {email}: {e.message}")
                raise e
            except Exception as e:
                log.error(f"Error during login process for {email}: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred during login.")


class AddUser(Mutation):
    """ GraphQL Mutation to add a new user. (Public Access for signup) """
    class Arguments:
        username = String(required=True)
        email = String(required=True)
        password = String(required=True)
        role = String(required=True, description="User role, e.g., 'user' or 'admin'")
    user = Field(lambda: UserObject)

    @staticmethod
    def mutate(root, info, username, email, password, role):
        """Handles new user creation."""
        log.info(f"AddUser attempt: email={email}, role={role}")
        # Conditional auth check only if creating an admin role
        if role == "admin":
            log.info("Attempting to create an admin user, checking requester's permissions.")
            try:
                requesting_user = get_authenticated_user(info.context)
                if requesting_user.role != "admin":
                    log.warning(f"Permission denied: User {requesting_user.id} attempted to create admin.")
                    raise GraphQLError("Only admin users can add new admin users")
                log.info(f"Admin creation authorized for requester ID {requesting_user.id}")
            except GraphQLError as auth_error:
                log.warning(f"Auth error during admin creation check: {auth_error.message}")
                raise auth_error
            except Exception as e:
                log.error(f"Authorization check error during addUser: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred during authorization.")

        # --- Validate Inputs ---
        try:
            # --- Use the updated password policy check, passing username and email ---
            log.debug("Checking password strength.")
            is_password_strong(password, username=username, email=email) # Pass user info

            log.debug(f"Validating email format for: {email}")
            normalized_email = validate_user_email(email) # Raises ValueError
            log.debug(f"Email format valid, normalized to: {normalized_email}")
        except ValueError as ve:
            log.warning(f"Input validation failed: {ve}")
            raise GraphQLError(str(ve))

        # Add other validations for username if needed
        if not username or len(username) < 3:
            raise GraphQLError("Username must be at least 3 characters long.")

        if role not in ["user", "admin"]:
            log.warning(f"Invalid role provided: {role}")
            raise GraphQLError("Invalid role specified. Must be 'user' or 'admin'.")

        with Session() as session:
            log.debug(f"Checking for existing user with email: {normalized_email}")
            existing_user = session.query(User).filter(User.email == normalized_email).first()
            if existing_user:
                log.warning(f"User creation failed: Email {normalized_email} already exists.")
                raise GraphQLError("Cannot create user: Email already exists.")

            try:
                # Hash password - validation should have happened in is_password_strong
                log.debug("Hashing password.")
                password_hash = hash_password(password) # Raises ValueError on internal error
            except ValueError as ve:
                log.warning(f"Password hashing validation failed: {ve}")
                raise GraphQLError(str(ve))
            except Exception as e:
                log.error(f"Error hashing password for {normalized_email}: {e}", exc_info=True)
                raise GraphQLError("An internal error occurred while securing user credentials.")

            new_user = User(
                username=username,
                email=normalized_email,
                password_hash=password_hash,
                role=role
            )
            log.debug(f"New user object created for email: {normalized_email}")

            try:
                log.debug("Adding new user to session.")
                session.add(new_user)
                log.debug("Committing transaction.")
                session.commit()
                session.refresh(new_user)
                log.info(f"User created successfully: ID={new_user.id}, Email={normalized_email}")
            except IntegrityError as e:
                session.rollback()
                log.error(f"Database integrity error adding user {normalized_email}: {e}", exc_info=True)
                if 'users_email_key' in str(e).lower() or 'unique constraint' in str(e).lower():
                    raise GraphQLError("Could not create user: Email may already be in use.")
                else:
                    raise GraphQLError("Could not create user due to a data conflict.")
            except Exception as e:
                session.rollback()
                log.error(f"Unexpected error saving user {normalized_email} to database: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while saving the user.")

            return AddUser(user=new_user)


class UpdateUser(Mutation):
    """Updates authenticated user's details (username, email, password)."""
    class Arguments:
        username = String(description="New username for the user.")
        email = String(description="New email for the user.")
        password = String(description="New password.")
        current_password = String(description="Required if setting a new password.")
    user = Field(lambda: UserObject)

    @authd_user # Decorator ensures user is logged in
    def mutate(root, info, username=None, email=None, password=None, current_password=None):
        """Handles updating the authenticated user's profile."""
        try:
            user_to_update = get_authenticated_user(info.context)
            log.info(f"UpdateUser attempt for user ID: {user_to_update.id}")
        except GraphQLError as e:
            log.error(f"Auth error after decorator in updateUser: {e}", exc_info=True)
            raise GraphQLError("Authentication required.")

        made_changes = False
        with Session() as session:
            try:
                log.debug(f"Attaching user ID {user_to_update.id} to session for update.")
                session.add(user_to_update)

                # --- Handle Password Change ---
                if password is not None:
                    log.debug(f"Password change requested for user ID {user_to_update.id}")
                    if current_password is None:
                        log.warning(f"Password change failed for user {user_to_update.id}: Current password not provided.")
                        raise GraphQLError("Current password is required to set a new password.")

                    log.debug(f"Verifying current password for user ID {user_to_update.id}")
                    verify_password(user_to_update.password_hash, current_password) # Raises GraphQLError

                    log.debug(f"Checking new password strength for user ID {user_to_update.id}")
                    try:
                        # --- Pass current username/email to policy check ---
                        is_password_strong(password, username=user_to_update.username, email=user_to_update.email) # Raises ValueError
                    except ValueError as ve:
                        log.warning(f"Password policy violation for user {user_to_update.id}: {ve}")
                        raise GraphQLError(str(ve))

                    log.debug(f"Hashing new password for user ID {user_to_update.id}")
                    try:
                        new_password_hash = hash_password(password) # Raises ValueError
                        if new_password_hash != user_to_update.password_hash:
                            user_to_update.password_hash = new_password_hash
                            made_changes = True
                            log.info(f"User ID {user_to_update.id} password hash updated.")
                        else: log.info(f"New password hash is same as old for user ID {user_to_update.id}.")
                    except ValueError as ve:
                        log.warning(f"Password hashing validation failed during update for user {user_to_update.id}: {ve}")
                        raise GraphQLError(str(ve))
                    except Exception as e:
                        log.error(f"Error hashing new password for user {user_to_update.id}: {e}", exc_info=True)
                        raise GraphQLError("Internal error securing new password.")

                # --- Handle Email Change ---
                if email is not None and email != user_to_update.email:
                    log.debug(f"Email change requested for user ID {user_to_update.id} to {email}")
                    try:
                        normalized_email = validate_user_email(email) # Raises ValueError
                        log.debug(f"New email format valid, normalized to: {normalized_email}")
                    except ValueError as ve:
                        log.warning(f"Invalid new email format for user {user_to_update.id}: {ve}")
                        raise GraphQLError(str(ve))

                    log.debug(f"Checking email uniqueness for {normalized_email} (excluding user {user_to_update.id})")
                    existing = session.query(User).filter(User.email == normalized_email, User.id != user_to_update.id).first()
                    if existing:
                        log.warning(f"Email update failed for user {user_to_update.id}: Email {normalized_email} already in use.")
                        raise GraphQLError("Cannot update: Email already in use by another account.")

                    user_to_update.email = normalized_email
                    made_changes = True
                    log.info(f"User ID {user_to_update.id} email updated to {normalized_email}.")

                # --- Handle Username Change ---
                if username is not None and username != user_to_update.username:
                    log.debug(f"Username change requested for user ID {user_to_update.id} to {username}")
                    # Add username validation here if needed
                    if not username or len(username) < 3:
                        raise GraphQLError("Username must be at least 3 characters long.")
                    user_to_update.username = username
                    made_changes = True
                    log.info(f"User ID {user_to_update.id} username updated to {username}.")

                # --- Commit Transaction ---
                if made_changes:
                    log.debug(f"Committing updates for user ID {user_to_update.id}")
                    session.commit()
                    session.refresh(user_to_update)
                    log.info(f"User ID {user_to_update.id} profile updated in DB.")
                else:
                    log.info(f"No effective changes requested for user ID {user_to_update.id}.")

                return UpdateUser(user=user_to_update)

            except GraphQLError as e:
                session.rollback()
                log.warning(f"Update failed for user {user_to_update.id}: {e.message}")
                raise e
            except IntegrityError as e:
                session.rollback()
                log.error(f"DB integrity error updating user {user_to_update.id}: {e}", exc_info=True)
                if 'users_email_key' in str(e).lower() or ('unique constraint' in str(e).lower() and 'email' in str(e).lower()):
                    raise GraphQLError("Could not update user: Email may already be in use.")
                else: raise GraphQLError("Could not update user due to a data conflict.")
            except Exception as e:
                session.rollback()
                log.error(f"Error updating user {user_to_update.id}: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while updating user details.")


class ApplyToJob(Mutation):
    """ GraphQL Mutation for a user to apply to a job. (Requires Auth) """
    class Arguments: job_id = Int(required=True)
    job_application = Field(lambda: JobApplicationObject)
    @authd_user
    def mutate(root, info, job_id):
        """Handles applying the authenticated user to a job."""
        try:
            auth_user = get_authenticated_user(info.context); user_id = auth_user.id
            log.info(f"User {user_id} attempting to apply for job {job_id}")
        except GraphQLError as e: log.error(f"Auth error after decorator in applyToJob: {e}", exc_info=True); raise GraphQLError("Authentication required.")
        with Session() as session:
            try:
                job_exists = session.query(Job).filter(Job.id == job_id).first()
                if not job_exists: log.warning(f"ApplyToJob failed: Job {job_id} not found."); raise GraphQLError(f"Job with ID {job_id} not found.")
                existing_application = session.query(JobApplication).filter(JobApplication.user_id == user_id, JobApplication.job_id == job_id).first()
                if existing_application: log.warning(f"User {user_id} already applied to job {job_id}."); raise GraphQLError("You have already applied to this job")
                log.debug(f"Creating job application for user {user_id}, job {job_id}")
                job_application = JobApplication(user_id=user_id, job_id=job_id)
                session.add(job_application); session.commit(); session.refresh(job_application)
                log.info(f"User {user_id} successfully applied to job {job_id}. App ID: {job_application.id}")
                return ApplyToJob(job_application=job_application)
            except GraphQLError as e: session.rollback(); log.warning(f"ApplyToJob failed for user {user_id}, job {job_id}: {e.message}"); raise e
            except Exception as e: session.rollback(); log.error(f"Error applying user {user_id} to job {job_id}: {e}", exc_info=True); raise GraphQLError("An internal server error occurred while applying to the job.")


class DeleteUser(Mutation):
    """ GraphQL Mutation to delete a user. (Requires Auth) """
    class Arguments: user_id = Int(required=True)
    success = Boolean()
    @authd_user
    def mutate(root, info, user_id):
        """Handles deletion of a user account."""
        try: requesting_user = get_authenticated_user(info.context); log.info(f"DeleteUser attempt: Requester={requesting_user.id}, Target={user_id}")
        except GraphQLError as e: log.error(f"Auth error after decorator in deleteUser: {e}", exc_info=True); raise GraphQLError("Authentication required.")
        is_self_delete = (requesting_user.id == user_id); is_admin_request = (requesting_user.role == "admin")
        if not (is_admin_request or is_self_delete): log.warning(f"DeleteUser denied: User {requesting_user.id} not authorized to delete user {user_id}."); raise GraphQLError("Not authorized to delete this user")
        if is_admin_request and is_self_delete:
            log.debug(f"Admin user {user_id} attempting self-delete, checking admin count.")
            with Session() as session_check:
                try:
                    admin_count = session_check.query(User).filter(User.role == "admin").count(); log.debug(f"Current admin count: {admin_count}")
                    if admin_count <= 1: log.warning(f"Admin self-delete denied: User {user_id} is the last admin."); raise GraphQLError("Cannot delete the last admin account.")
                except Exception as e: log.error(f"Error checking admin count during self-delete attempt by admin {user_id}: {e}", exc_info=True); raise GraphQLError("Could not verify admin count; deletion disallowed as precaution.")
        with Session() as session:
            try:
                log.debug(f"Querying for user to delete: ID={user_id}")
                user_to_delete = session.query(User).filter(User.id == user_id).first()
                if not user_to_delete: log.warning(f"DeleteUser failed: User {user_id} not found."); raise GraphQLError("User not found")
                log.debug(f"Deleting user object: ID={user_id}"); session.delete(user_to_delete); log.debug(f"Committing deletion for user ID={user_id}"); session.commit()
                log.info(f"User ID {user_id} deleted successfully by user ID {requesting_user.id}.")
                return DeleteUser(success=True)
            except GraphQLError as e: session.rollback(); log.warning(f"DeleteUser failed for target {user_id}: {e.message}"); raise e
            except IntegrityError as e: session.rollback(); log.error(f"DB integrity error deleting user {user_id}: {e}", exc_info=True); raise GraphQLError("Could not delete user due to database constraints (e.g., related records).")
            except Exception as e: session.rollback(); log.error(f"Error deleting user {user_id} from database: {e}", exc_info=True); raise GraphQLError("An internal server error occurred while deleting the user.")