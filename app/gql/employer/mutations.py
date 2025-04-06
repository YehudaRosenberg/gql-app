# app/gql/employer/mutations.py

from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError
import logging

# --- Import decorator and Session/Models ---
from app.gql.types import EmployerObject
from app.db.database import Session
from app.db.models import Employer # User not needed here unless checking creator later
from app.utils import admin_user # Use admin_user decorator for all these

class AddEmployer(Mutation):
    """ Adds a new employer. Requires admin privileges. """
    class Arguments:
        name = String(required=True)
        contact_email = String(required=True)
        industry = String(required=True)

    employer = Field(lambda: EmployerObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, name, contact_email, industry):
        # Consider adding email format validation for contact_email
        with Session() as session:
            try:
                # Optional: Check if employer with same name/email already exists?
                existing = session.query(Employer).filter(Employer.contact_email == contact_email).first()
                if existing:
                    raise GraphQLError(f"Employer with contact email {contact_email} already exists.")

                employer = Employer(name=name, contact_email=contact_email, industry=industry)
                session.add(employer)
                session.commit()
                session.refresh(employer)
                return AddEmployer(employer=employer)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error adding employer: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while adding the employer.")


class UpdateEmployer(Mutation):
    """ Updates an existing employer. Requires admin privileges. """
    class Arguments:
        employer_id = Int(required=True) # Changed from id for clarity
        name = String()
        contact_email = String()
        industry = String()

    employer = Field(lambda: EmployerObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, employer_id, name=None, contact_email=None, industry=None):
        with Session() as session:
            try:
                employer = session.query(Employer).filter(Employer.id == employer_id).first()
                if not employer:
                    raise GraphQLError("Employer not found")

                # Check for email uniqueness if contact_email is being changed
                if contact_email is not None and contact_email != employer.contact_email:
                    existing = session.query(Employer).filter(Employer.contact_email == contact_email).first()
                    if existing:
                        raise GraphQLError(f"Another employer with contact email {contact_email} already exists.")
                    employer.contact_email = contact_email

                # Update other fields if provided
                if name is not None:
                    employer.name = name
                if industry is not None:
                    employer.industry = industry

                session.commit()
                session.refresh(employer)
                return UpdateEmployer(employer=employer)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                session.rollback()
                logging.error(f"Error updating employer(id={employer_id}): {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while updating the employer.")


class DeleteEmployer(Mutation):
    """ Deletes an employer. Requires admin privileges. """
    class Arguments:
        id = Int(required=True)

    success = Boolean()

    @admin_user # Enforces auth + admin role
    def mutate(root, info, id):
        with Session() as session:
            try:
                employer = session.query(Employer).filter(Employer.id == id).first()
                if not employer:
                    raise GraphQLError("Employer not found")

                # Consider implications: what happens to Jobs associated with this employer?
                # If Job.employer_id is non-nullable, deletion might fail unless jobs are
                # deleted first or handled by DB cascades (ON DELETE CASCADE/SET NULL).
                session.delete(employer)
                session.commit()
                return DeleteEmployer(success=True)
            except GraphQLError as e:
                session.rollback()
                raise e
            except Exception as e:
                # Catch potential IntegrityError if DB constraints prevent deletion (e.g., related jobs exist)
                from sqlalchemy.exc import IntegrityError
                if isinstance(e, IntegrityError):
                    session.rollback()
                    logging.warning(f"Could not delete employer(id={id}) due to integrity constraint: {e}")
                    raise GraphQLError("Cannot delete employer, possibly due to existing associated jobs.")
                else:
                    session.rollback()
                    logging.error(f"Error deleting employer(id={id}): {e}", exc_info=True)
                    raise GraphQLError("An internal server error occurred while deleting the employer.")