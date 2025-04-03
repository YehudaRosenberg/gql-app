# app/gql/user/mutations.py

# --- Add logging and potentially specific DB exceptions ---
import logging
from sqlalchemy.exc import IntegrityError # To catch DB constraint violations specifically

from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError

from app.utils import generate_token, verify_password, get_authenticated_user, hash_password
from app.db.database import Session
from app.db.models import User, JobApplication, Job # Import Job model for ApplyToJob check
from app.gql.types import UserObject, JobApplicationObject


logging.basicConfig(level=logging.INFO)


class LoginUser(Mutation):
    """ GraphQL Mutation for user login. """
    class Arguments:
        email = String(required=True)
        password = String(required=True)
    token = String()
    @staticmethod
    def mutate(root, info, email, password):
        with Session() as session:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                raise GraphQLError("Invalid email or password")
            try:
                verify_password(user.password_hash, password) # Raises GraphQLError on failure
                token = generate_token(email)
                return LoginUser(token=token)
            except GraphQLError as e: # Catch verify_password error
                raise e
            except Exception as e:
                logging.error(f"Error during login process for {email}: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred during login.")


class AddUser(Mutation):
    """ GraphQL Mutation to add a new user. """
    class Arguments:
        username = String(required=True)
        email = String(required=True)
        password = String(required=True)
        role = String(required=True)
    user = Field(lambda: UserObject)
    @staticmethod
    def mutate(root, info, username, email, password, role):
        if role == "admin":
            try:
                requesting_user = get_authenticated_user(info.context)
                if requesting_user.role != "admin":
                    raise GraphQLError("Only admin users can add new admin users")
            except GraphQLError as auth_error:
                raise auth_error
            except Exception as e:
                logging.error(f"Authorization check error during addUser: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred during authorization.")

        with Session() as session:
            existing_user = session.query(User).filter(User.email == email).first()
            if existing_user:
                # Make error generic but specific enough
                raise GraphQLError("Cannot create user: Email already exists.")

            try:
                password_hash = hash_password(password)
            except Exception as e:
                logging.error(f"Error hashing password for {email}: {e}", exc_info=True)
                raise GraphQLError("An internal error occurred while securing user credentials.")

            if role not in ["user", "admin"]:
                raise GraphQLError("Invalid role specified. Must be 'user' or 'admin'.")

            new_user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role
            )

            try:
                session.add(new_user)
                session.commit()
                session.refresh(new_user)
            except IntegrityError as e:
                session.rollback()
                logging.error(f"Database integrity error adding user {email}: {e}", exc_info=True)
                raise GraphQLError("Could not create user due to a data conflict.")
            except Exception as e:
                session.rollback()
                logging.error(f"Unexpected error saving user {email} to database: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while saving the user.")

            return AddUser(user=new_user)


class ApplyToJob(Mutation):
    """ GraphQL Mutation for a user to apply to a job. """
    class Arguments:
        job_id = Int(required=True)
    job_application = Field(lambda: JobApplicationObject)
    def mutate(root, info, job_id):
        try:
            auth_user = get_authenticated_user(info.context)
            user_id = auth_user.id
        except GraphQLError as auth_error:
            raise auth_error
        except Exception as e:
            logging.error(f"Authentication error during applyToJob: {e}", exc_info=True)
            raise GraphQLError("Authentication error.")

        with Session() as session:
            try:
                # Check if job exists
                job_exists = session.query(Job).filter(Job.id == job_id).first()
                if not job_exists:
                    raise GraphQLError(f"Job with ID {job_id} not found.")

                existing_application = session.query(JobApplication).filter(
                    JobApplication.user_id == user_id,
                    JobApplication.job_id == job_id
                ).first()
                if existing_application:
                    raise GraphQLError("You have already applied to this job")

                job_application = JobApplication(user_id=user_id, job_id=job_id)
                session.add(job_application)
                session.commit()
                session.refresh(job_application)
                return ApplyToJob(job_application=job_application)
            except GraphQLError as e: # Re-raise specific GQL errors
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error applying user {user_id} to job {job_id}: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while applying to the job.")


class DeleteUser(Mutation):
    """ GraphQL Mutation to delete a user. """
    class Arguments:
        user_id = Int(required=True)
    success = Boolean()
    def mutate(root, info, user_id):
        try:
            requesting_user = get_authenticated_user(info.context)
        except GraphQLError as auth_error:
            raise auth_error
        except Exception as e:
            logging.error(f"Authentication error during deleteUser for target {user_id}: {e}", exc_info=True)
            raise GraphQLError("Authentication error.")

        if not (requesting_user.role == "admin" or requesting_user.id == user_id):
            raise GraphQLError("Not authorized to delete this user")

        with Session() as session:
            try:
                user_to_delete = session.query(User).filter(User.id == user_id).first()
                if not user_to_delete:
                    raise GraphQLError("User not found")
                if user_to_delete.role == "admin":
                    admin_count = session.query(User).filter(User.role == "admin").count()
                    if admin_count <= 1 and user_to_delete.id == requesting_user.id:
                         raise GraphQLError("Cannot delete the last admin account.")

                session.delete(user_to_delete)
                session.commit()
                return DeleteUser(success=True)
            except GraphQLError as e: # Re-raise specific GQL errors
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error deleting user {user_id} from database: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while deleting the user.")