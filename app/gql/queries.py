from graphene import ObjectType, List, Field, Int
from sqlalchemy.orm import selectinload, joinedload, Session
from graphql import GraphQLError
import logging
from app.utils import authd_user, admin_user, get_authenticated_user
from app.gql.types import JobObject, EmployerObject, UserObject, JobApplicationObject
from app.db.database import Session # Import Session factory directly
from app.db.models import Job, Employer, User, JobApplication

# Configure logging
logging.basicConfig(level=logging.INFO)

class Query(ObjectType):
    """
    Root Query type. All fields require authentication unless otherwise noted.
    """
    # --- 'me' FIELD ---
    me = Field(UserObject, description="Get the currently authenticated user's details.")

    # --- Existing Fields (Auth rules noted) ---
    jobs = List(JobObject, description="Get a list of all jobs. (Requires Auth)")
    job = Field(JobObject, id=Int(required=True), description="Get a specific job by ID. (Requires Auth)")
    employers = List(EmployerObject, description="Get a list of all employers. (Requires Auth)")
    employer = Field(EmployerObject, id=Int(required=True), description="Get a specific employer by ID. (Requires Auth)")
    users = List(UserObject, description="Get a list of all users. (Admin Only)") # Admin Only
    job_applications = List(JobApplicationObject, description="Get job applications. (Requires Auth - Filtered by user role)") # Filtered


    # --- Resolver for 'me' ---
    @staticmethod
    @authd_user # Ensures user is logged in
    def resolve_me(root, info):
        """ Resolves the 'me' field, returning the authenticated user. """
        try:
            # The decorator already authenticated, now just get the user object
            user = get_authenticated_user(info.context)
            # Optional: Log access
            # logging.info(f"User {user.id} resolved 'me' field.")
            return user
        except GraphQLError as e:
            # Should technically be caught by decorator, but good failsafe
            raise e
        except Exception as e:
            logging.error(f"Error resolving 'me': {e}", exc_info=True)
            raise GraphQLError("Could not retrieve current user details due to an internal error.")

    @staticmethod
    @authd_user
    def resolve_job_applications(root, info):
        """ Resolves job applications. Admins see all, users see only their own. """
        try:
            requesting_user = get_authenticated_user(info.context)
            with Session() as session:
                query = session.query(JobApplication).options(
                    selectinload(JobApplication.user),
                    selectinload(JobApplication.job).selectinload(Job.employer)
                )
                if requesting_user.role != "admin":
                    query = query.filter(JobApplication.user_id == requesting_user.id)
                return query.all()
        except GraphQLError as e: raise e
        except Exception as e:
            logging.error(f"Error resolving job_applications: {e}", exc_info=True)
            raise GraphQLError("Could not retrieve job applications due to an internal error.")

    @staticmethod
    @authd_user
    def resolve_job(root, info, id):
        """ Resolves a single job by ID. """
        try:
            with Session() as session:
                job = session.query(Job).options(
                    selectinload(Job.employer), selectinload(Job.applications)
                ).filter(Job.id == id).first()
                if not job: raise GraphQLError("Job not found.")
                return job
        except GraphQLError as e: raise e
        except Exception as e:
            logging.error(f"Error resolving job(id={id}): {e}", exc_info=True)
            raise GraphQLError("Could not retrieve job details due to an internal error.")

    @staticmethod
    @authd_user
    def resolve_jobs(root, info):
        """ Resolves a list of all jobs. """
        try:
            with Session() as session:
                return session.query(Job).options(selectinload(Job.employer)).all()
        except Exception as e:
            logging.error(f"Error resolving jobs: {e}", exc_info=True)
            raise GraphQLError("Could not retrieve jobs due to an internal error.")

    @staticmethod
    @authd_user
    def resolve_employers(root, info):
        """ Resolves a list of all employers. """
        try:
            with Session() as session:
                return session.query(Employer).options(selectinload(Employer.jobs)).all()
        except Exception as e:
            logging.error(f"Error resolving employers: {e}", exc_info=True)
            raise GraphQLError("Could not retrieve employers due to an internal error.")

    @staticmethod
    @authd_user
    def resolve_employer(root, info, id):
        """ Resolves a single employer by ID. """
        try:
            with Session() as session:
                employer = session.query(Employer).options(
                    selectinload(Employer.jobs)
                ).filter(Employer.id == id).first()
                if not employer: raise GraphQLError("Employer not found.")
                return employer
        except GraphQLError as e: raise e
        except Exception as e:
            logging.error(f"Error resolving employer(id={id}): {e}", exc_info=True)
            raise GraphQLError("Could not retrieve employer details due to an internal error.")

    @staticmethod
    @admin_user # Remains Admin Only
    def resolve_users(root, info):
        """ Resolves a list of all users. (Admin Only) """
        try:
            with Session() as session:
                return session.query(User).options(selectinload(User.applications)).all()
        except Exception as e:
            logging.error(f"Error resolving users (admin access): {e}", exc_info=True)
            raise GraphQLError("Could not retrieve users due to an internal error.")