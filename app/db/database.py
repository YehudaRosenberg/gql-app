# app/db/database.py

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# We no longer need to import the static data here
# from app.db.data import employers_data, jobs_data, users_data, applications_data
from app.db.models import Base # We still need Base for metadata
# We might still need User if creating a default admin user is desired later,
# but not for basic empty startup. Models like Employer, Job, JobApplication aren't needed here anymore.
# from app.db.models import Employer, Job, User, JobApplication

# Keep hash_password if you plan to potentially create a default user programmatically later
# from app.utils import hash_password
import os

load_dotenv()

DB_URL = os.getenv("DB_URL")

engine = create_engine(DB_URL, echo=False) # Set echo=True for debugging SQL if needed
Session = sessionmaker(bind=engine)


def prepare_database():
    # --- REMOVED ---
    # Base.metadata.drop_all(engine) # Remove this line to prevent data loss on restart

    # --- KEEP ---
    # Create tables if they don't exist. If they exist, this does nothing.
    Base.metadata.create_all(engine)

    # --- REMOVED ---
    # No longer need a session or data seeding here if starting empty.
    """
    session = Session()

    # Remove employer seeding loop
    # for employer in employers_data:
    #     emp = Employer(**employer)
    #     session.add(emp)

    # Remove job seeding loop
    # for job in jobs_data:
    #     session.add(Job(**job))

    # Remove user seeding loop (unless you want a default admin user)
    # for user in users_data:
    #     user['password_hash'] = hash_password(user['password'])
    #     del user['password']
    #     session.add(User(**user))

    # Remove application seeding loop
    # for app in applications_data:
    #     session.add(JobApplication(**app))

    session.commit()
    session.close()
    """
    print("Database tables ensured.") # Optional: confirmation message