# app/gql/mutations.py

from graphene import ObjectType
# Import all mutation classes
from app.gql.job.mutations import AddJob, UpdateJob, DeleteJob
from app.gql.employer.mutations import AddEmployer, UpdateEmployer, DeleteEmployer
from app.gql.user.mutations import (
    LoginUser, AddUser, UpdateUser, ApplyToJob, DeleteUser
)


class Mutation(ObjectType):
    """
    Root Mutation type aggregating all mutations for the schema.
    Access control (authentication/authorization) is handled within
    each individual mutation's resolver/decorator.
    """
    # Job Mutations (Requires Admin)
    add_job = AddJob.Field()
    update_job = UpdateJob.Field()
    delete_job = DeleteJob.Field()

    # Employer Mutations (Requires Admin)
    add_employer = AddEmployer.Field()
    update_employer = UpdateEmployer.Field()
    delete_employer = DeleteEmployer.Field()

    # User Mutations
    login_user = LoginUser.Field()     # Public Access
    add_user = AddUser.Field()         # Public Access (Conditional auth inside for admin creation)
    update_user = UpdateUser.Field()   # Requires Authentication (Self-update)
    apply_to_job = ApplyToJob.Field()  # Requires Authentication
    delete_user = DeleteUser.Field()   # Requires Authentication (Admin or Self)