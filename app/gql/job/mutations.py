# app/gql/job/mutations.py

from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError
import logging

# --- Import decorator and Session/Models ---
from app.gql.types import JobObject
from app.db.database import Session
from app.db.models import Job, Employer # Import Employer to check employer_id validity
from app.utils import admin_user # Use admin_user decorator for all these

class AddJob(Mutation):
    """ Adds a new job. Requires admin privileges. """
    class Arguments:
        title = String(required=True)
        description = String(required=True)
        employer_id = Int(required=True)

    job = Field(lambda: JobObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, title, description, employer_id):
        with Session() as session:
            try:
                # Check if employer exists
                employer = session.query(Employer).filter(Employer.id == employer_id).first()
                if not employer:
                    raise GraphQLError(f"Employer with ID {employer_id} not found.")

                job = Job(title=title, description=description, employer_id=employer_id)
                session.add(job)
                session.commit()
                session.refresh(job)
                return AddJob(job=job)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error adding job: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while adding the job.")


class UpdateJob(Mutation):
    """ Updates an existing job. Requires admin privileges. """
    class Arguments:
        job_id = Int(required=True)
        title = String()
        description = String()
        employer_id = Int()

    job = Field(lambda: JobObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, job_id, title=None, description=None, employer_id=None):
        with Session() as session:
            try:
                job = session.query(Job).filter(Job.id == job_id).first()
                if not job:
                    raise GraphQLError("Job not found")

                # Check if new employer_id is valid if provided
                if employer_id is not None:
                    employer = session.query(Employer).filter(Employer.id == employer_id).first()
                    if not employer:
                        raise GraphQLError(f"Employer with ID {employer_id} not found.")
                    job.employer_id = employer_id

                # Update fields if provided
                if title is not None:
                    job.title = title
                if description is not None:
                    job.description = description

                session.commit()
                session.refresh(job)
                return UpdateJob(job=job)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error updating job(id={job_id}): {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while updating the job.")


class DeleteJob(Mutation):
    """ Deletes a job. Requires admin privileges. """
    class Arguments:
        id = Int(required=True) # Use 'id' consistently

    success = Boolean()

    @admin_user # Enforces auth + admin role
    def mutate(root, info, id):
        with Session() as session:
            try:
                job = session.query(Job).filter(Job.id == id).first()
                if not job:
                    raise GraphQLError("Job not found")

                # Consider implications: what happens to JobApplications for this job?
                # Depending on DB cascade rules or app logic, they might need handling.
                session.delete(job)
                session.commit()
                return DeleteJob(success=True)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error deleting job(id={id}): {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while deleting the job.")