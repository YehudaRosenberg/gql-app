from graphene import Mutation, String, Int, Field, Boolean
from graphql import GraphQLError
import logging
from sqlalchemy.exc import IntegrityError
from app.gql.types import EmployerObject
from app.db.database import Session
from app.db.models import Employer, Job
from app.utils import admin_user, validate_user_email

log = logging.getLogger(__name__)

class AddEmployer(Mutation):
    """ Creates a new employer profile (Admin Only). """
    class Arguments:
        name = String(required=True)
        contact_email = String(required=True)
        industry = String(required=True)
    employer = Field(lambda: EmployerObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, name, contact_email, industry):
        log.info(f"AddEmployer attempt: Name={name}, Email={contact_email}")

        # --- Validate Email Format ---
        try:
            log.debug(f"Validating contact email: {contact_email}")
            normalized_email = validate_user_email(contact_email) # Raises ValueError
            log.debug(f"Contact email validated and normalized: {normalized_email}")
        except ValueError as ve:
            log.warning(f"Invalid contact email format for AddEmployer: {ve}")
            raise GraphQLError(str(ve)) # Convert validation error to GraphQLError

        with Session() as session:
            try:
                # Check if employer with same normalized contact email already exists
                log.debug(f"Checking for existing employer with email: {normalized_email}")
                existing = session.query(Employer).filter(Employer.contact_email == normalized_email).first()
                if existing:
                    log.warning(f"AddEmployer failed: Employer with email {normalized_email} already exists.")
                    raise GraphQLError(f"Employer with contact email {normalized_email} already exists.")

                # Create and save new employer
                log.debug("Creating new Employer instance.")
                employer = Employer(
                    name=name,
                    contact_email=normalized_email, # Use normalized email
                    industry=industry
                )
                session.add(employer)
                session.commit()
                session.refresh(employer)
                log.info(f"Employer added successfully: ID={employer.id}, Name={name}")
                return AddEmployer(employer=employer)

            except GraphQLError as e: # Re-raise specific logical errors
                session.rollback()
                log.warning(f"Failed adding employer {name}: {e.message}")
                raise e
            except Exception as e: # Catch unexpected DB or other errors
                session.rollback()
                log.error(f"Error adding employer {name}: {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while adding the employer.")


class UpdateEmployer(Mutation):
    """ Updates an existing employer profile (Admin Only). """
    class Arguments:
        employer_id = Int(required=True)
        name = String()
        contact_email = String()
        industry = String()
    employer = Field(lambda: EmployerObject)

    @admin_user # Enforces auth + admin role
    def mutate(root, info, employer_id, name=None, contact_email=None, industry=None):
        log.info(f"UpdateEmployer attempt for ID: {employer_id}")
        made_changes = False

        # --- Validate Email Format if provided ---
        normalized_email = None
        if contact_email is not None:
            try:
                log.debug(f"Validating updated contact email: {contact_email}")
                normalized_email = validate_user_email(contact_email) # Raises ValueError
                log.debug(f"Updated contact email validated and normalized: {normalized_email}")
            except ValueError as ve:
                log.warning(f"Invalid contact email format for UpdateEmployer: {ve}")
                raise GraphQLError(str(ve))

        with Session() as session:
            try:
                # Find the employer to update
                log.debug(f"Fetching employer ID: {employer_id}")
                employer = session.query(Employer).filter(Employer.id == employer_id).first()
                if not employer:
                    log.warning(f"UpdateEmployer failed: Employer ID {employer_id} not found.")
                    raise GraphQLError("Employer not found")

                # Check for email uniqueness if contact_email is being changed
                if normalized_email is not None and normalized_email != employer.contact_email:
                    log.debug(f"Checking email uniqueness for {normalized_email} (excluding employer {employer_id})")
                    existing = session.query(Employer).filter(
                        Employer.contact_email == normalized_email,
                        Employer.id != employer_id # Exclude self
                    ).first()
                    if existing:
                        log.warning(f"UpdateEmployer failed: Email {normalized_email} already in use by employer {existing.id}.")
                        raise GraphQLError(f"Another employer with contact email {normalized_email} already exists.")
                    log.debug(f"Updating email for employer {employer_id} to {normalized_email}")
                    employer.contact_email = normalized_email
                    made_changes = True

                # Update other fields if provided and different
                if name is not None and employer.name != name:
                    log.debug(f"Updating name for employer {employer_id}")
                    # Add name validation if needed
                    employer.name = name
                    made_changes = True
                if industry is not None and employer.industry != industry:
                    log.debug(f"Updating industry for employer {employer_id}")
                    employer.industry = industry
                    made_changes = True

                # Commit only if changes were made
                if made_changes:
                    log.debug(f"Committing updates for employer ID {employer_id}")
                    session.commit()
                    session.refresh(employer)
                    log.info(f"Employer updated successfully: ID={employer_id}")
                else:
                    log.info(f"No effective changes requested for employer ID={employer_id}")

                return UpdateEmployer(employer=employer)

            except GraphQLError as e: # Re-raise specific logical errors
                session.rollback()
                log.warning(f"Failed updating employer {employer_id}: {e.message}")
                raise e
            except Exception as e: # Catch unexpected DB or other errors
                session.rollback()
                log.error(f"Error updating employer(id={employer_id}): {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while updating the employer.")


class DeleteEmployer(Mutation):
    """ Deletes an employer profile (Admin Only). Fails if jobs are associated. """
    class Arguments:
        id = Int(required=True)
    success = Boolean()

    @admin_user # Enforces auth + admin role
    def mutate(root, info, id):
        log.info(f"DeleteEmployer attempt for ID: {id}")
        with Session() as session:
            try:
                # Find the employer
                log.debug(f"Fetching employer ID: {id}")
                employer = session.query(Employer).filter(Employer.id == id).first()
                if not employer:
                    log.warning(f"DeleteEmployer failed: Employer ID {id} not found.")
                    raise GraphQLError("Employer not found")

                # --- Check for Associated Jobs ---
                log.debug(f"Checking for jobs associated with employer ID: {id}")
                job_count = session.query(Job).filter(Job.employer_id == id).count()
                if job_count > 0:
                    log.warning(f"DeleteEmployer failed: Employer ID {id} has {job_count} associated jobs.")
                    raise GraphQLError(f"Cannot delete employer: {job_count} job(s) are still associated with this employer.")
                log.debug(f"No associated jobs found for employer ID: {id}. Proceeding with delete.")
                # --- End Check ---

                # Delete the employer
                session.delete(employer)
                session.commit()
                log.info(f"Employer deleted successfully: ID={id}")
                return DeleteEmployer(success=True)

            except GraphQLError as e: # Re-raise specific logical errors
                session.rollback()
                log.warning(f"Failed deleting employer {id}: {e.message}")
                raise e
            except IntegrityError as e: # Catch potential DB constraint violations (should be less likely now)
                session.rollback()
                log.warning(f"Could not delete employer(id={id}) due to unexpected integrity constraint: {e}")
                raise GraphQLError("Cannot delete employer due to database constraints.")
            except Exception as e: # Catch other unexpected errors
                session.rollback()
                log.error(f"Error deleting employer(id={id}): {e}", exc_info=True)
                raise GraphQLError("An internal server error occurred while deleting the employer.")