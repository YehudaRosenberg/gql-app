from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, selectinload

Base = declarative_base()

class Employer(Base):
    __tablename__ = "employers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    contact_email = Column(String)
    industry = Column(String)

    # Apply selectinload to efficiently load related jobs
    jobs = relationship("Job", back_populates="employer", lazy="selectin")

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String)
    description = Column(String)
    employer_id = Column(Integer, ForeignKey("employers.id"))

    employer = relationship("Employer", back_populates="jobs", lazy="selectin")

    # Apply selectinload to efficiently load related applications
    applications = relationship("JobApplication", back_populates="job", lazy="selectin")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String)
    email = Column(String)
    password_hash = Column(String)
    role = Column(String)

    # Apply selectinload to efficiently load related job applications
    applications = relationship("JobApplication", back_populates="user", lazy="selectin")

class JobApplication(Base):
    __tablename__ = "job_applications"

    id  = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    job_id = Column(Integer, ForeignKey("jobs.id"))

    user = relationship("User", back_populates="applications", lazy="selectin")
    job = relationship("Job", back_populates="applications", lazy="selectin")
