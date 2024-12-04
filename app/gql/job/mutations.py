from graphene import Mutation, String, Int, Field, Boolean
from app.gql.types import JobObject
from app.db.database import Session
from app.db.models import Job
from app.utils import admin_user


class AddJob(Mutation):
    class Arguments:
        title = String(required=True)
        description = String(required=True)
        employer_id = Int(required=True)

    job = Field(lambda: JobObject)

    @admin_user
    def mutate(root, info, title, description, employer_id):
        job = Job(title=title, description=description, employer_id=employer_id)
        session = Session()
        session.add(job)
        session.commit()
        session.refresh(job)
        return AddJob(job=job)


class UpdateJob(Mutation):
    class Arguments:
        job_id = Int(required=True)
        title = String()
        description = String()
        employer_id = Int()

    job = Field(lambda: JobObject)

    @admin_user
    def mutate(root, info, job_id, title=None, description=None, employer_id=None):
        session = Session()
        job = session.query(Job).filter(Job.id == job_id).first()
        # job = session.query(Job).options(joinedload(Job.employer)).filter(Job.id == job_id).first()

        if not job:
            raise Exception("Job not found")

        if title is not None:
            job.title = title

        if description is not None:
            job.description = description

        if employer_id is not None:
            job.employer_id = employer_id

        session.commit()
        session.refresh(job)
        session.close()
        return UpdateJob(job=job)


class DeleteJob(Mutation):
    class Arguments:
        id = Int(required=True)

    success = Boolean()

    @admin_user
    def mutate(root, info, id):
        session = Session()
        job = session.query(Job).filter(Job.id == id).first()

        if not job:
            raise Exception("Job not found")

        session.delete(job)
        session.commit()
        session.close()
        return DeleteJob(success=True)

