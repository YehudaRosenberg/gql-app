# create_admin.py
import logging
import sys
import os
from getpass import getpass # For securely getting password input

# This allows the script to find your 'app' module assuming
# the script is run from the project root directory.
sys.path.append(os.getcwd())

try:
    from app.db.database import Session, prepare_database
    from app.db.models import User
    from app.utils import hash_password, is_password_strong, validate_user_email
except ImportError as e:
    print(f"Error: Could not import necessary application modules: {e}")
    print("Please ensure this script is in your project's root directory and your virtual environment is active.")
    print("Also, ensure __init__.py files are present in 'app', 'app/db', 'app/gql' etc. to make them packages.")
    sys.exit(1)

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

def create_new_admin_user():
    log.info("--- Admin User Creation Script ---")

    try:
        username = input("Enter username for the new admin: ").strip()
        if not username:
            log.error("Username cannot be empty.")
            return

        email = input("Enter email for the new admin: ").strip()
        if not email:
            log.error("Email cannot be empty.")
            return

        while True:
            password = getpass("Enter a strong temporary password for the new admin: ")
            password_confirm = getpass("Confirm the password: ")
            if password == password_confirm:
                if not password: # Check if password is empty after confirmation
                    log.warning("Password cannot be empty. Please try again.")
                    continue
                break
            else:
                log.warning("Passwords do not match. Please try again.")

        role = "admin" # Setting the role explicitly to admin

        # --- Validate Inputs using your app's utilities ---
        log.info("Validating inputs...")
        try:
            normalized_email = validate_user_email(email) # Validates and normalizes
            log.info(f"Email normalized to: {normalized_email}")
            # is_password_strong will raise ValueError if policy is not met
            is_password_strong(password, username=username, email=normalized_email)
            log.info("Inputs (email, password strength) validated successfully.")
        except ValueError as ve:
            log.error(f"Input validation failed: {ve}")
            return

        # --- Hash the password ---
        log.info("Hashing password...")
        try:
            password_hashed = hash_password(password)
            log.info("Password hashed successfully.")
        except ValueError as ve: # hash_password might raise ValueError on internal error
            log.error(f"Failed to hash password: {ve}")
            return
        except Exception as e:
            log.error(f"An unexpected error occurred during password hashing: {e}", exc_info=True)
            return


        # --- Interact with Database ---
        with Session() as session:
            log.info(f"Checking if user with email '{normalized_email}' already exists...")
            existing_user = session.query(User).filter(User.email == normalized_email).first()
            if existing_user:
                log.error(f"Cannot create admin: User with email '{normalized_email}' already exists (ID: {existing_user.id}, Role: {existing_user.role}).")
                if existing_user.role == 'admin':
                    log.info("If you forgot the password for this existing admin, consider a password reset script instead.")
                return

            log.info(f"Creating new admin user object: Username='{username}', Email='{normalized_email}', Role='{role}'")
            new_admin = User(
                username=username,
                email=normalized_email,
                password_hash=password_hashed,
                role=role
            )

            try:
                session.add(new_admin)
                session.commit()
                session.refresh(new_admin) # To get auto-generated fields like ID
                log.info(f"--- Successfully created new admin user ---")
                log.info(f"  ID:       {new_admin.id}")
                log.info(f"  Username: {new_admin.username}")
                log.info(f"  Email:    {new_admin.email}")
                log.info(f"  Role:     {new_admin.role}")
                log.info("You should now be able to log in using these credentials via the application.")
                log.warning("IMPORTANT: For security, please log in and change this temporary password through the application's 'update user' functionality if available.")
            except Exception as e:
                session.rollback()
                log.error(f"Database error: Could not save new admin user. {e}", exc_info=True)

    except KeyboardInterrupt:
        log.info("\nAdmin creation process cancelled by user.")
    except Exception as e:
        log.error(f"An unexpected error occurred during the admin creation process: {e}", exc_info=True)

if __name__ == "__main__":
    # Ensure the database schema is created if it hasn't been already.
    # If your application has been run before, the tables should exist.
    # This is a safety measure.
    log.info("Preparing database (ensuring tables exist)...")
    try:
        prepare_database()
        log.info("Database preparation complete.")
    except Exception as e:
        log.error(f"Could not prepare database: {e}. The script might fail if tables don't exist.")
        # You might choose to exit if DB preparation is critical and fails
        # sys.exit("Exiting due to database preparation failure.")

    create_new_admin_user()