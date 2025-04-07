from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError
import logging
from app.gql.types import JobObject
from app.db.database import Session
from app.db.models import Job, Employer
from app.utils import admin_user

log = logging.getLogger(__name__)

class AddJob(Mutation):
    """ Creates a new job posting (Admin Only). """
    class Arguments:
        title = String(required=True)
        description = String(required=True)
        employer_id = Int(required=True)
    job = Field(lambda: JobObject)
    @admin_user
    def mutate(root, info, title, description, employer_id):
        with Session() as session:
            try:
                employer = session.query(Employer).filter(Employer.id == employer_id).first()
                if not employer: raise GraphQLError(f"Employer with ID {employer_id} not found.")
                job = Job(title=title, description=description, employer_id=employer_id)
                session.add(job); session.commit(); session.refresh(job)
                log.info(f"Job added: ID={job.id}, Title={title}")
                return AddJob(job=job)
            except GraphQLError as e: session.rollback(); log.warning(f"Failed adding job: {e.message}"); raise e
            except Exception as e: session.rollback(); log.error(f"Error adding job: {e}", exc_info=True); raise GraphQLError("An internal server error occurred while adding the job.")


class UpdateJob(Mutation):
    """ Updates an existing job posting (Admin Only). """
    class Arguments:
        job_id = Int(required=True)
        title = String()
        description = String()
        employer_id = Int()
    job = Field(lambda: JobObject)
    @admin_user
    def mutate(root, info, job_id, title=None, description=None, employer_id=None):
        with Session() as session:
            try:
                job = session.query(Job).filter(Job.id == job_id).first()
                if not job: raise GraphQLError("Job not found")
                made_changes = False
                if employer_id is not None:
                    employer = session.query(Employer).filter(Employer.id == employer_id).first()
                    if not employer: raise GraphQLError(f"Employer with ID {employer_id} not found.")
                    if job.employer_id != employer_id: job.employer_id = employer_id; made_changes = True
                if title is not None and job.title != title: job.title = title; made_changes = True
                if description is not None and job.description != description: job.description = description; made_changes = True
                if made_changes: session.commit(); session.refresh(job); log.info(f"Job updated: ID={job_id}")
                else: log.info(f"No effective changes for job ID={job_id}")
                return UpdateJob(job=job)
            except GraphQLError as e: session.rollback(); log.warning(f"Failed updating job {job_id}: {e.message}"); raise e
            except Exception as e: session.rollback(); log.error(f"Error updating job(id={job_id}): {e}", exc_info=True); raise GraphQLError("An internal server error occurred while updating the job.")


class DeleteJob(Mutation):
    """ Deletes a job posting (Admin Only). """
    class Arguments: id = Int(required=True)
    success = Boolean()
    @admin_user
    def mutate(root, info, id):
        with Session() as session:
            try:
                job = session.query(Job).filter(Job.id == id).first()
                if not job: raise GraphQLError("Job not found")
                session.delete(job); session.commit()
                log.info(f"Job deleted: ID={id}")
                return DeleteJob(success=True)
            except GraphQLError as e: session.rollback(); log.warning(f"Failed deleting job {id}: {e.message}"); raise e
            except Exception as e: session.rollback(); log.error(f"Error deleting job(id={id}): {e}", exc_info=True); raise GraphQLError("An internal server error occurred while deleting the job.")