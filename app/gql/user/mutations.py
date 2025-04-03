import string
from random import choices
from traceback import walk_tb

from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError
from sqlalchemy.sql.functions import current_user

from app.utils import generate_token, verify_password, get_authenticated_user
from app.db.database import Session
from app.db.models import User, JobApplication
from app.gql.types import UserObject, JobApplicationObject
from app.utils import hash_password, authd_user_same_as




class LoginUser(Mutation):
    class Arguments:
        email = String(required=True)
        password = String(required=True)

    token = String()

    @staticmethod
    def mutate(root, info, email, password):
        session = Session()
        user = session.query(User).filter(User.email == email).first()

        if not user:
            raise GraphQLError("Invalid email or password")

        verify_password(user.password_hash, password)

        token = generate_token(email)

        return LoginUser(token=token)

class AddUser(Mutation):
    class Arguments:
        username = String(required=True)
        email = String(required=True)
        password = String(required=True)
        role = String(required=True)

    user = Field(lambda: UserObject)



    @staticmethod
    def mutate(root, info, username, email, password, role):
        if role == "admin":
            current_user = get_authenticated_user(info.context)
            if current_user != "admin":
                raise GraphQLError("Only admin users can add new admin users")

        session = Session()

        user = session.query(User).filter(User.email == email).first()

        if user:
            raise GraphQLError("User already exists")

        password_hash = hash_password(password)

        user = User(username=username, email=email, password_hash=password_hash, role=role)
        session.add(user)
        session.commit()
        session.refresh(user)


        return AddUser(user=user)

class ApplyToJob(Mutation):
    class Arguments:
        user_id = Int(required=True)
        job_id = Int(required=True)

    job_application = Field(lambda: JobApplicationObject)

    @authd_user_same_as
    def mutate(root, info, user_id, job_id):
        session = Session()



        existing_application = session.query(JobApplication).filter(
            JobApplication.user_id == user_id,
            JobApplication.job_id == job_id
        ).first()

        if existing_application:
            raise GraphQLError("This user already applied to this job")

        job_application = JobApplication(user_id=user_id, job_id=job_id)
        session.add(job_application)
        session.commit()
        session.refresh(job_application)
        return ApplyToJob(job_application=job_application)


class DeleteUser(Mutation):
    """
    GraphQL Mutation to delete a user.
    Requires authentication. Allows admins to delete any user,
    and regular users to delete only their own account.
    """
    class Arguments:
        user_id = Int(required=True) # The ID of the user to delete

    success = Boolean() # Returns true if deletion is successful

    # No specific decorator needed here as logic is conditional
    def mutate(root, info, user_id):
        try:
            # Check who is making the request
            requesting_user = get_authenticated_user(info.context)
        except GraphQLError as auth_error:
            raise auth_error # Re-raise authentication errors
        except Exception as e:
            raise GraphQLError(f"Authentication error: {e}")

        # Authorization check: Allow if admin OR if user is deleting themselves
        if not (requesting_user.role == "admin" or requesting_user.id == user_id):
            raise GraphQLError("Not authorized to delete this user")

        with Session() as session:
            try:
                # Find the user to delete
                user_to_delete = session.query(User).filter(User.id == user_id).first()

                if not user_to_delete:
                    raise GraphQLError("User not found")

                # Optional: Add check here to prevent deletion of last admin?

                # Delete the user
                session.delete(user_to_delete)
                session.commit()

                return DeleteUser(success=True)

            except GraphQLError as e:
                session.rollback() # Rollback on known errors (like not found) if commit hasn't happened
                raise e
            except Exception as e:
                session.rollback() # Rollback on unexpected database errors
                raise GraphQLError(f"Error deleting user from database: {e}")
